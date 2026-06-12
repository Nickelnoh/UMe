// ignore_for_file: avoid_web_libraries_in_flutter, deprecated_member_use

import 'dart:html' as html;
import 'dart:typed_data';

Future<bool> saveAttachmentBytes({
  required Uint8List bytes,
  required String name,
  required String mimeType,
}) async {
  final safeName = name.trim().isEmpty ? 'ume-file' : name.trim();
  final type = mimeType.trim().isEmpty ? 'application/octet-stream' : mimeType.trim();
  final blob = html.Blob(<Object>[bytes], type);
  final url = html.Url.createObjectUrlFromBlob(blob);

  final anchor = html.AnchorElement(href: url)
    ..download = safeName
    ..style.display = 'none';

  html.document.body?.children.add(anchor);
  anchor.click();
  anchor.remove();
  html.Url.revokeObjectUrl(url);

  return true;
}
