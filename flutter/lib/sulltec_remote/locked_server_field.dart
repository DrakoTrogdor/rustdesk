import 'package:flutter/material.dart';

/// Deliberately not a wrapper around upstream's `serverSettingsTextFormField`:
/// that helper builds its own `InputDecoration`, so there is no seam to add the
/// lock glyph through.
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
