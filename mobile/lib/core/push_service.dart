// ignore_for_file: avoid_print

import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import 'api_client.dart';

class PushService {
  static final FirebaseMessaging _messaging = FirebaseMessaging.instance;

  static final FlutterLocalNotificationsPlugin _localNotifications =
      FlutterLocalNotificationsPlugin();

  static const String _webVapidKey =
      'RpTvhkqn1AP-9LRObNiX1TI65fNZ0mhEYgAmyYQt9aI';

  static const String _channelId = 'ume_messages';
  static const String _channelName = 'UMe messages';
  static const String _channelDescription =
      'Notifications for new UMe messages';

  static bool _localNotificationsReady = false;
  static bool _listenersReady = false;

  static Future<bool> shouldShowPermissionBanner() async {
    try {
      final settings = await _messaging.getNotificationSettings();

      print('PUSH BANNER CHECK STATUS: ${settings.authorizationStatus}');

      return settings.authorizationStatus == AuthorizationStatus.notDetermined;
    } catch (e) {
      print('PUSH PERMISSION BANNER CHECK ERROR: $e');
      return false;
    }
  }

  static Future<void> requestPermissionOnly() async {
    try {
      final settings = await _messaging.requestPermission(
        alert: true,
        badge: true,
        sound: true,
        provisional: false,
      );

      print('PUSH PERMISSION STATUS: ${settings.authorizationStatus}');
    } catch (e) {
      print('PUSH PERMISSION REQUEST ERROR: $e');
      rethrow;
    }
  }

  static Future<void> registerIfPermissionAlreadyGranted() async {
    try {
      final settings = await _messaging.getNotificationSettings();

      print('PUSH REGISTER IF GRANTED STATUS: ${settings.authorizationStatus}');

      if (settings.authorizationStatus == AuthorizationStatus.authorized ||
          settings.authorizationStatus == AuthorizationStatus.provisional) {
        await initializeAndRegister();
      }
    } catch (e) {
      print('PUSH REGISTER IF GRANTED ERROR: $e');
      rethrow;
    }
  }

  static Future<void> initializeAndRegister() async {
    try {
      print('PUSH INIT START');

      await requestPermissionOnly();

      final settings = await _messaging.getNotificationSettings();

      print('PUSH SETTINGS AFTER REQUEST: ${settings.authorizationStatus}');

      if (settings.authorizationStatus != AuthorizationStatus.authorized &&
          settings.authorizationStatus != AuthorizationStatus.provisional) {
        print('PUSH NOT AUTHORIZED: ${settings.authorizationStatus}');
        return;
      }

      if (!kIsWeb) {
        await _setupLocalNotifications();
      }

      _setupListeners();

      final token = await _getToken();

      print(
        'PUSH TOKEN VALUE: ${token == null ? "NULL" : "OK length=${token.length}"}',
      );

      if (token == null || token.isEmpty) {
        print('PUSH TOKEN EMPTY, REQUEST NOT SENT');
        return;
      }

      await _sendTokenToBackend(token);

      print('PUSH INIT DONE');
    } catch (e) {
      print('PUSH INIT ERROR: $e');
      rethrow;
    }
  }

  static void _setupListeners() {
    if (_listenersReady) {
      print('PUSH LISTENERS ALREADY READY');
      return;
    }

    FirebaseMessaging.onMessage.listen((RemoteMessage message) {
      print('PUSH FOREGROUND MESSAGE: ${message.messageId}');

      if (!kIsWeb) {
        _showForegroundNotification(message);
      }
    });

    _messaging.onTokenRefresh.listen((token) async {
      print('PUSH TOKEN REFRESHED length=${token.length}');
      await _sendTokenToBackend(token);
    });

    _listenersReady = true;
    print('PUSH LISTENERS READY');
  }

  static Future<String?> _getToken() async {
    print('PUSH GET TOKEN START, kIsWeb=$kIsWeb');

    if (kIsWeb) {
      final token = await _messaging.getToken(
        vapidKey: _webVapidKey,
      );

      print(
        'PUSH GET WEB TOKEN RESULT: ${token == null ? "NULL" : "OK length=${token.length}"}',
      );

      return token;
    }

    final token = await _messaging.getToken();

    print(
      'PUSH GET MOBILE TOKEN RESULT: ${token == null ? "NULL" : "OK length=${token.length}"}',
    );

    return token;
  }

  static Future<void> _sendTokenToBackend(String token) async {
    try {
      final platform = kIsWeb ? 'web' : defaultTargetPlatform.name;

      print('PUSH TOKEN SEND START: platform=$platform length=${token.length}');

      await ApiClient.post(
        '/push/token',
        {
          'token': token,
          'platform': platform,
        },
      );

      print('PUSH TOKEN REGISTERED: $platform');
    } catch (e) {
      print('PUSH TOKEN SEND ERROR: $e');
      rethrow;
    }
  }

  static Future<void> deleteTokenFromBackend() async {
    try {
      final token = await _getToken();

      if (token == null || token.isEmpty) {
        print('PUSH TOKEN DELETE SKIPPED: empty token');
        return;
      }

      await ApiClient.post(
        '/push/token/delete',
        {
          'token': token,
        },
      );

      print('PUSH TOKEN DELETED');
    } catch (e) {
      print('PUSH TOKEN DELETE ERROR: $e');
      rethrow;
    }
  }

  static Future<void> _setupLocalNotifications() async {
    if (_localNotificationsReady) {
      print('PUSH LOCAL NOTIFICATIONS ALREADY READY');
      return;
    }

    const androidSettings = AndroidInitializationSettings(
      '@mipmap/ic_launcher',
    );

    const initializationSettings = InitializationSettings(
      android: androidSettings,
    );

    await _localNotifications.initialize(
      settings: initializationSettings,
    );

    const channel = AndroidNotificationChannel(
      _channelId,
      _channelName,
      description: _channelDescription,
      importance: Importance.high,
    );

    await _localNotifications
        .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>()
        ?.createNotificationChannel(channel);

    _localNotificationsReady = true;
    print('PUSH LOCAL NOTIFICATIONS READY');
  }

  static Future<void> _showForegroundNotification(RemoteMessage message) async {
    final notification = message.notification;

    final title =
        notification?.title ?? message.data['title'] ?? 'UMe Messenger';

    final body =
        notification?.body ?? message.data['body'] ?? 'Новое сообщение';

    const androidDetails = AndroidNotificationDetails(
      _channelId,
      _channelName,
      channelDescription: _channelDescription,
      importance: Importance.high,
      priority: Priority.high,
      icon: '@mipmap/ic_launcher',
    );

    const details = NotificationDetails(
      android: androidDetails,
    );

    await _localNotifications.show(
      id: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      title: title,
      body: body,
      notificationDetails: details,
      payload: message.data.toString(),
    );
  }
}