import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../config.dart';
import 'secure_storage.dart';

class WebSocketService {
  WebSocketChannel? _channel;
  StreamSubscription? _subscription;

  final _eventsController = StreamController<Map<String, dynamic>>.broadcast();

  Stream<Map<String, dynamic>> get events => _eventsController.stream;

  Future<void> connect() async {
    final token = await SecureStorage.getAccessToken();

    if (token == null || token.isEmpty) return;

    final uri = Uri.parse('${AppConfig.wsBaseUrl}/ws?token=$token');

    _channel = WebSocketChannel.connect(uri);

    _subscription = _channel!.stream.listen(
      (event) {
        try {
          final decoded = jsonDecode(event.toString());

          if (decoded is Map<String, dynamic>) {
            _eventsController.add(decoded);
          }
        } catch (_) {}
      },
      onError: (_) {},
      onDone: () {},
    );
  }

  void send(Map<String, dynamic> event) {
    _channel?.sink.add(jsonEncode(event));
  }

  Future<void> disconnect() async {
    await _subscription?.cancel();
    await _channel?.sink.close();

    _subscription = null;
    _channel = null;
  }

  Future<void> dispose() async {
    await disconnect();
    await _eventsController.close();
  }
}