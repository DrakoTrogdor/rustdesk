import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../common.dart';
import '../models/model.dart';
import '../models/platform_model.dart';

// ── SullTec login-credential injection (docs/PLAN-credential-injection.md) ────────────────────────
// A console-launched session can type a stored login credential (username/password) into the remote
// as keystrokes, without the operator ever seeing the secret. The console hands the spawned client an
// operator token + backend URL via env (ST_LOGON_TOKEN / ST_LOGON_URL — the operator backend, NOT the
// client API server) — read here via mainGetEnv. The calls hit
// /api/devices/{id}/common/login-credentials,
// which that operator token authenticates: a list that carries no secret, then a per-credential
// reveal that releases one plaintext and is audited. Inert when not launched from the console (the
// env vars are absent).

String _injectBase() => bind.mainGetEnv(key: 'ST_LOGON_URL').trim();
String _injectToken() => bind.mainGetEnv(key: 'ST_LOGON_TOKEN').trim();

/// True when this client was launched from the console (the inject endpoints are reachable).
bool consoleInjectAvailable() => _injectBase().isNotEmpty && _injectToken().isNotEmpty;

/// Fetch then type a login credential's `field` ('username' | 'password') into the remote `id`,
/// asking which credential when more than one applies. The secret is never shown in the UI.
Future<void> injectLoginCredential(
    FFI ffi, String id, SessionID sessionId, String field) async {
  final base = _injectBase();
  final token = _injectToken();
  if (base.isEmpty || token.isEmpty) {
    showToast(translate('Not launched from the console'));
    return;
  }
  final headers = {
    'Authorization': 'Bearer $token',
    'Content-Type': 'application/json',
  };
  try {
    final injectBase = '$base/api/devices/$id/common/login-credentials';
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
    // Both identifiers are in the PATH, so the body carries neither: the backend refuses a target
    // named in the address AND in the body, agreeing or not.
    final fetchResp = await http
        .post(Uri.parse('$injectBase/$credId/reveal'), headers: headers)
        .timeout(const Duration(seconds: 10));
    if (fetchResp.statusCode != 200) {
      showToast('${translate('Credential fetch failed')} (${fetchResp.statusCode})');
      return;
    }
    // The fetch body carries the plaintext secret. Decode it in its own guard: a FormatException's
    // toString() embeds the source it failed to parse, so letting it reach the outer `$e` toast would
    // print the password — defeating the "secret is never shown" guarantee. Use a generic message.
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

/// When several login credentials apply to a device, ask the operator which one (label + username).
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
