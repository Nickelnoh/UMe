import 'dart:async';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'secure_storage.dart';

class AttachmentDownloadProgress {
  final int downloadedBytes;
  final int? totalBytes;

  const AttachmentDownloadProgress({
    required this.downloadedBytes,
    required this.totalBytes,
  });

  double? get value {
    final total = totalBytes;

    if (total == null || total <= 0) return null;

    return (downloadedBytes / total).clamp(0.0, 1.0);
  }
}

class DownloadedAttachment {
  final String url;
  final String name;
  final String mimeType;
  final Uint8List bytes;
  final DateTime downloadedAt;

  const DownloadedAttachment({
    required this.url,
    required this.name,
    required this.mimeType,
    required this.bytes,
    required this.downloadedAt,
  });

  int get sizeBytes => bytes.lengthInBytes;
}

class AttachmentDownloadStore {
  static final Map<String, DownloadedAttachment> _cache = {};
  static final Map<String, Future<DownloadedAttachment>> _running = {};

  static DownloadedAttachment? get(String url) {
    final normalized = url.trim();

    if (normalized.isEmpty) return null;

    return _cache[normalized];
  }

  static bool isDownloaded(String url) => get(url) != null;

  static Future<DownloadedAttachment> download({
    required String url,
    required String name,
    String mimeType = 'application/octet-stream',
    void Function(AttachmentDownloadProgress progress)? onProgress,
  }) {
    final normalized = url.trim();

    if (normalized.isEmpty) {
      return Future.error(Exception('Пустой адрес файла'));
    }

    final cached = _cache[normalized];

    if (cached != null) {
      onProgress?.call(
        AttachmentDownloadProgress(
          downloadedBytes: cached.sizeBytes,
          totalBytes: cached.sizeBytes,
        ),
      );
      return Future.value(cached);
    }

    final running = _running[normalized];

    if (running != null) return running;

    final future = _downloadFresh(
      url: normalized,
      name: name,
      mimeType: mimeType,
      onProgress: onProgress,
    );

    _running[normalized] = future;

    future.whenComplete(() {
      _running.remove(normalized);
    });

    return future;
  }

  static Future<DownloadedAttachment> _downloadFresh({
    required String url,
    required String name,
    required String mimeType,
    void Function(AttachmentDownloadProgress progress)? onProgress,
  }) async {
    final request = http.Request('GET', Uri.parse(url));
    final token = await SecureStorage.getAccessToken();

    if (token != null && token.isNotEmpty) {
      request.headers['Authorization'] = 'Bearer $token';
    }

    final client = http.Client();

    late final http.StreamedResponse response;

    try {
      response = await client.send(request).timeout(
            const Duration(minutes: 5),
          );
    } catch (_) {
      client.close();
      rethrow;
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      client.close();
      throw Exception('HTTP ${response.statusCode}');
    }

    final contentLength = response.contentLength;
    final total = contentLength != null && contentLength > 0 ? contentLength : null;
    final chunks = <List<int>>[];
    var downloaded = 0;

    onProgress?.call(
      AttachmentDownloadProgress(downloadedBytes: 0, totalBytes: total),
    );

    try {
      await for (final chunk in response.stream) {
        chunks.add(chunk);
        downloaded += chunk.length;

        onProgress?.call(
          AttachmentDownloadProgress(
            downloadedBytes: downloaded,
            totalBytes: total,
          ),
        );
      }
    } finally {
      client.close();
    }

    final bytes = Uint8List(downloaded);
    var offset = 0;

    for (final chunk in chunks) {
      bytes.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }

    final resolvedMimeType = response.headers['content-type']?.split(';').first.trim();

    final entry = DownloadedAttachment(
      url: url,
      name: name.trim().isEmpty ? 'file' : name.trim(),
      mimeType: resolvedMimeType == null || resolvedMimeType.isEmpty
          ? mimeType
          : resolvedMimeType,
      bytes: bytes,
      downloadedAt: DateTime.now(),
    );

    _cache[url] = entry;

    onProgress?.call(
      AttachmentDownloadProgress(
        downloadedBytes: entry.sizeBytes,
        totalBytes: entry.sizeBytes,
      ),
    );

    return entry;
  }

  static String formatSize(int bytes) {
    if (bytes < 1024) return '$bytes Б';

    final kb = bytes / 1024;
    if (kb < 1024) return '${kb.toStringAsFixed(kb < 10 ? 1 : 0)} КБ';

    final mb = kb / 1024;
    if (mb < 1024) return '${mb.toStringAsFixed(mb < 10 ? 1 : 0)} МБ';

    final gb = mb / 1024;
    return '${gb.toStringAsFixed(gb < 10 ? 1 : 0)} ГБ';
  }
}
