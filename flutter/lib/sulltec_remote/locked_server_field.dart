import 'package:flutter/material.dart';

/// Read-only rendering of a server-settings field whose option the console has
/// fixed through OVERWRITE_SETTINGS.
///
/// Deliberately not a wrapper around upstream's `serverSettingsTextFormField`:
/// that helper builds its own `InputDecoration`, so there is no seam to add the
/// lock glyph through, and its IME hardening (autocorrect, suggestions,
/// personalized learning) exists to protect typed input — which cannot happen
/// in a field the operator is not allowed to edit.
///
/// Pass `labelText` null where the caller already renders the label beside the
/// field, matching upstream's `showLabelText: false`.
TextFormField sulltecLockedServerField({
  required TextEditingController controller,
  required String errorMsg,
  String? labelText,
  EdgeInsetsGeometry? contentPadding,
}) {
  return TextFormField(
    controller: controller,
    readOnly: true,
    decoration: InputDecoration(
      labelText: labelText,
      errorText: errorMsg.isEmpty ? null : errorMsg,
      contentPadding: contentPadding,
      suffixIcon: Icon(Icons.lock_outline, size: 16),
    ),
  );
}
