import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../common.dart';
import '../models/model.dart';
import '../models/platform_model.dart';

({String url, String token}) _consoleLogon(SessionID sessionId) {
  var url = '';
  var token = '';
  try {
    final m = jsonDecode(bind.sessionGetConsoleLogon(sessionId: sessionId));
    if (m is Map) {
      url = (m['url'] ?? '').toString().trim();
      token = (m['token'] ?? '').toString().trim();
    }
  } catch (_) {}
  if (url.isEmpty && token.isEmpty) {
    url = bind.mainGetEnv(key: 'ST_LOGON_URL').trim();
    token = bind.mainGetEnv(key: 'ST_LOGON_TOKEN').trim();
  }
  return (url: url, token: token);
}

bool consoleInjectAvailable(SessionID sessionId) {
  final logon = _consoleLogon(sessionId);
  return logon.url.isNotEmpty && logon.token.isNotEmpty;
}

Future<void> injectLoginCredential(
    FFI ffi, String id, SessionID sessionId, String field) async {
  final logon = _consoleLogon(sessionId);
  final base = logon.url;
  final token = logon.token;
  if (base.isEmpty || token.isEmpty) {
    showToast(translate('Not launched from the console'));
    return;
  }
  final headers = {
    'Authorization': 'Bearer $token',
    'Content-Type': 'application/json',
  };
  try {
    final injectBase = '$base/api/devices/key/$id/common/login-credentials';
    final listResp = await http
        .get(Uri.parse('$injectBase/list'), headers: headers)
        .timeout(const Duration(seconds: 10));
    if (listResp.statusCode != 200) {
      showToast('${translate('Failed to load credentials')} (${listResp.statusCode})');
      return;
    }
    final decoded = jsonDecode(listResp.body);
    final List list = decoded is List ? decoded : <dynamic>[];
    if (list.isEmpty) {
      showToast(translate('No login credentials for this device'));
      return;
    }
    Map? chosen;
    if (list.length == 1) {
      chosen = list.first as Map;
    } else {
      chosen = await _pickLoginCredential(ffi, list);
    }
    if (chosen == null) return;
    final credId = chosen['id']?.toString() ?? '';
    if (credId.isEmpty) return;
    final fetchResp = await http
        .post(Uri.parse('$injectBase/key/$credId/reveal'), headers: headers)
        .timeout(const Duration(seconds: 10));
    if (fetchResp.statusCode != 200) {
      showToast('${translate('Credential fetch failed')} (${fetchResp.statusCode})');
      return;
    }
    // Decode the fetch body in its own guard: a FormatException's toString() embeds the source it
    // failed to parse, so letting it reach the outer `$e` toast would print the password —
    // defeating the "secret is never shown" guarantee.
    final Map m;
    try {
      final decodedFetch = jsonDecode(fetchResp.body);
      m = decodedFetch is Map ? decodedFetch : <dynamic, dynamic>{};
    } catch (_) {
      showToast(translate('Credential fetch failed'));
      return;
    }
    var value = (field == 'username' ? m['username'] : m['password'])?.toString() ?? '';
    if (field == 'username') {
      final domain = (m['domain'] ?? '').toString();
      if (domain.isNotEmpty && !value.contains('\\') && !value.contains('@')) {
        value = '$domain\\$value';
      }
    }
    if (value.isEmpty) {
      showToast(translate('Credential is empty'));
      return;
    }
    bind.sessionInputString(sessionId: sessionId, value: value);
  } catch (e) {
    showToast('${translate('Injection failed')}: $e');
  }
}

Future<Map?> _pickLoginCredential(FFI ffi, List list) async {
  return await ffi.dialogManager.show<Map?>(
      (setState, close, context) => CustomAlertDialog(
            title: Text(translate('Choose a credential')),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: list.map<Widget>((c) {
                final m = c as Map;
                final label = (m['label'] ?? '').toString();
                final user = (m['username'] ?? '').toString();
                return ListTile(
                  title: Text(label.isEmpty ? '(unnamed)' : label),
                  subtitle: user.isEmpty ? null : Text(user),
                  onTap: () => close(m),
                );
              }).toList(),
            ),
            actions: [
              dialogButton('Cancel', onPressed: () => close(null), isOutline: true),
            ],
            onCancel: () => close(null),
          ));
}
