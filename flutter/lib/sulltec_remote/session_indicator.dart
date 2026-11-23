import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:get/get.dart';

import '../common.dart';
import '../models/model.dart';
import '../models/platform_model.dart';

class _WindowsSessionsState {
  bool refreshPending = false;
  final names = <String>[].obs;
}

final _windowsSessionsState = Expando<_WindowsSessionsState>();

_WindowsSessionsState _stateOf(FfiModel model) =>
    _windowsSessionsState[model] ??= _WindowsSessionsState();

List<String> _names(String sessions) {
  try {
    return (jsonDecode(sessions) as List)
        .map((s) => s['name']?.toString() ?? '')
        .toList();
  } catch (_) {
    return [];
  }
}

bool sulltecShowWindowsSessions(FfiModel model, Map<String, dynamic> evt) {
  _stateOf(model).names.value =
      _names(evt['windows_sessions']?.toString() ?? '');
  return true;
}

void _showSessionPicker(FfiModel model, String sessions) {
  final dialogManager = model.parent.target?.dialogManager;
  if (dialogManager == null) return;
  final list = jsonDecode(sessions) as List;
  final sids = list.map((s) => s['sid'].toString()).toList();
  final names = list.map((s) => s['name']?.toString() ?? '').toList();
  final current = names.indexOf(model.currentWindowsSession.value);
  var selected = sids[current >= 0 ? current : 0];
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    submit() {
      bind.sessionSendSelectedSessionId(
          sessionId: model.sessionId, sid: selected);
      final i = sids.indexOf(selected);
      sulltecHandleCurrentWindowsSession(
          model, {'sid': selected, 'session_name': names[i]});
      close();
    }

    return CustomAlertDialog(
      title: Text(translate('Switch session')),
      content: ComboBox(
          keys: sids,
          values: names,
          initialKey: selected,
          onChanged: (value) => selected = value),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('Connect', onPressed: submit, isOutline: false),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

void sulltecHandleCurrentWindowsSession(
    FfiModel model, Map<String, dynamic> evt) {
  final name = evt['session_name']?.toString() ?? '';
  model.currentWindowsSession.value = name;
  model.cachedPeerData.windowsSession = name;
  if (evt.isEmpty) {
    _windowsSessionsState[model] = null;
  } else {
    final sessions = evt['windows_sessions'];
    if (sessions != null) {
      final state = _stateOf(model);
      state.names.value = _names(sessions.toString());
      if (state.refreshPending) {
        state.refreshPending = false;
        _showSessionPicker(model, sessions.toString());
      }
    }
  }
}

Widget sulltecSessionIndicator(FFI ffi, {required double height}) {
  /// Mirrors `u32::MAX` on the Rust side — see
  /// `sulltec_remote::connection::windows_sessions_refresh_msg`.
  const refreshSentinel = '4294967295';

  return Obx(() {
    final session = ffi.ffiModel.currentWindowsSession.value;
    if (session.isEmpty) return const Offstage();
    final names = _stateOf(ffi.ffiModel).names;
    final others = names.length > 1 ? ' +${names.length - 1}' : '';
    return Tooltip(
      message: [...names, translate("Click to switch session")].join('\n'),
      child: InkWell(
        onTap: () {
          _stateOf(ffi.ffiModel).refreshPending = true;
          bind.sessionSendSelectedSessionId(
              sessionId: ffi.sessionId, sid: refreshSentinel);
        },
        child: Container(
          height: height,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          alignment: Alignment.center,
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.people_alt_outlined, size: 18),
            const SizedBox(width: 4),
            ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 200),
              child: Text(session,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 13)),
            ),
            if (others.isNotEmpty)
              Text(others, style: const TextStyle(fontSize: 13)),
          ]),
        ),
      ),
    );
  });
}
