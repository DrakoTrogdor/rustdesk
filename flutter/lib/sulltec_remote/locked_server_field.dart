import 'package:flutter/material.dart';

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
