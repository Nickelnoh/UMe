import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'secure_storage.dart';

class ApiClient {
  static const String _defaultBaseUrl = 'http://127.0.0.1:8000';

  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: _defaultBaseUrl,
  );

  static Uri uri(String path) {
    if (path.startsWith('http://') || path.startsWith('https://')) {
      return Uri.parse(path);
    }

    final normalizedPath = path.startsWith('/') ? path : '/$path';
    return Uri.parse('$baseUrl$normalizedPath');
  }

  static String absoluteUrl(String? path) {
    if (path == null || path.isEmpty) return '';

    if (path.startsWith('http://') || path.startsWith('https://')) {
      return path;
    }

    final normalizedPath = path.startsWith('/') ? path : '/$path';
    return '$baseUrl$normalizedPath';
  }

  static void _log(String message) {
    if (kDebugMode) {
      debugPrint(message);
    }
  }

  static Future<Map<String, String>> _headers({
    bool withAuth = true,
  }) async {
    final headers = <String, String>{
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };

    if (withAuth) {
      final token = await SecureStorage.getAccessToken();

      if (token != null && token.isNotEmpty) {
        headers['Authorization'] = 'Bearer $token';
      }
    }

    return headers;
  }

  static dynamic _decodeResponse(http.Response response) {
    dynamic body;

    if (response.body.isNotEmpty) {
      try {
        body = jsonDecode(response.body);
      } catch (_) {
        body = response.body;
      }
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      return body;
    }

    if (body is Map && body['detail'] != null) {
      final detail = body['detail'];

      if (detail is String) {
        throw Exception(detail);
      }

      throw Exception(jsonEncode(detail));
    }

    throw Exception('HTTP ${response.statusCode}: ${response.body}');
  }

  static Future<dynamic> get(
    String path, {
    bool withAuth = true,
  }) async {
    final requestUri = uri(path);

    _log('[API GET START] $requestUri');

    try {
      final response = await http
          .get(
            requestUri,
            headers: await _headers(withAuth: withAuth),
          )
          .timeout(const Duration(seconds: 60));

      _log('[API GET DONE] $requestUri -> ${response.statusCode}');

      return _decodeResponse(response);
    } on TimeoutException {
      _log('[API GET TIMEOUT] $requestUri');
      throw Exception('Сервер не ответил вовремя: GET $path');
    } catch (e) {
      _log('[API GET ERROR] $requestUri -> $e');
      rethrow;
    }
  }

  static Future<dynamic> post(
    String path,
    Map<String, dynamic> body, {
    bool withAuth = true,
  }) async {
    final requestUri = uri(path);

    _log('[API POST START] $requestUri');
    _log('[API POST BODY] ${jsonEncode(body)}');

    try {
      final response = await http
          .post(
            requestUri,
            headers: await _headers(withAuth: withAuth),
            body: jsonEncode(body),
          )
          .timeout(const Duration(seconds: 60));

      _log('[API POST DONE] $requestUri -> ${response.statusCode}');

      return _decodeResponse(response);
    } on TimeoutException {
      _log('[API POST TIMEOUT] $requestUri');
      throw Exception('Сервер не ответил вовремя: POST $path');
    } catch (e) {
      _log('[API POST ERROR] $requestUri -> $e');
      rethrow;
    }
  }

  static Future<dynamic> uploadBytes({
    required String path,
    required Uint8List bytes,
    required String filename,
    Map<String, String> fields = const {},
  }) async {
    final requestUri = uri(path);

    _log('[API UPLOAD START] $requestUri');

    try {
      final request = http.MultipartRequest('POST', requestUri);

      final token = await SecureStorage.getAccessToken();

      if (token != null && token.isNotEmpty) {
        request.headers['Authorization'] = 'Bearer $token';
      }

      request.fields.addAll(fields);

      request.files.add(
        http.MultipartFile.fromBytes(
          'uploaded_file',
          bytes,
          filename: filename,
        ),
      );

      final streamedResponse = await request.send().timeout(
            const Duration(seconds: 120),
          );

      final response = await http.Response.fromStream(streamedResponse);

      _log('[API UPLOAD DONE] $requestUri -> ${response.statusCode}');

      return _decodeResponse(response);
    } on TimeoutException {
      _log('[API UPLOAD TIMEOUT] $requestUri');
      throw Exception('Сервер не ответил вовремя: UPLOAD $path');
    } catch (e) {
      _log('[API UPLOAD ERROR] $requestUri -> $e');
      rethrow;
    }
  }
}