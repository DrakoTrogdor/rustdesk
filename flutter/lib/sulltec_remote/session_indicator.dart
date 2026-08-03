import 'package:flutter/material.dart';
import 'package:get/get.dart';

import '../common.dart';
import '../models/model.dart';
import '../models/platform_model.dart';

/// SullTec: the RDS / multi-session indicator in the remote toolbar.
///
/// Shows which Windows session the operator is connected to. Tapping it asks the host to
/// re-enumerate its sessions and re-open the picker, so a user who logged on *after* connect
/// appears and can be switched to.
///
/// Hidden until a session has been picked — which means it only ever appears on multi-session
/// hosts, since a single-session host never surfaces the picker and leaves the field empty.
///
/// `height` is passed in because the toolbar's own theme constants are library-private to
/// `remote_toolbar.dart`; this keeps the indicator visually consistent without exporting them.
Widget sulltecSessionIndicator(FFI ffi, {required double height}) {
  /// The sentinel the host reads as "re-enumerate my sessions and push the fresh list back",
  /// rather than as a session to switch to. Mirrors `u32::MAX` on the Rust side — see
  /// `sulltec_remote::connection::windows_sessions_refresh_msg`.
  const refreshSentinel = '4294967295';

  return Obx(() {
    final session = ffi.ffiModel.currentWindowsSession.value;
    if (session.isEmpty) return const Offstage();
    return Tooltip(
      message:
          '${translate("Connected to session")}: $session\n${translate("Click to switch session")}',
      child: InkWell(
        onTap: () => bind.sessionSendSelectedSessionId(
            sessionId: ffi.sessionId, sid: refreshSentinel),
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
          ]),
        ),
      ),
    );
  });
}
