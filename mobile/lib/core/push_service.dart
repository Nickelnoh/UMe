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

      return settings.authorizationStatus == AuthorizationStatus.notDetermined;
    } catch (e) {
      if (kDebugMode) {
        print('PUSH PERMISSION BANNER CHECK ERROR: $e');
      }

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

      if (kDebugMode) {
        print('PUSH PERMISSION STATUS: ${settings.authorizationStatus}');
      }
    } catch (e) {
      if (kDebugMode) {
        print('PUSH PERMISSION REQUEST ERROR: $e');
      }
    }
  }

  static Future<void> registerIfPermissionAlreadyGranted() async {
    try {
      final settings = await _messaging.getNotificationSettings();

      if (settings.authorizationStatus == AuthorizationStatus.authorized ||
          settings.authorizationStatus == AuthorizationStatus.provisional) {
        await initializeAndRegister();
      }
    } catch (e) {
      if (kDebugMode) {
        print('PUSH REGISTER IF GRANTED ERROR: $e');
      }
    }
  }

  static Future<void> initializeAndRegister() async {
    try {
      await requestPermissionOnly();

      final settings = await _messaging.getNotificationSettings();

      if (settings.authorizationStatus != AuthorizationStatus.authorized &&
          settings.authorizationStatus != AuthorizationStatus.provisional) {
        if (kDebugMode) {
          print('PUSH NOT AUTHORIZED: ${settings.authorizationStatus}');
        }
        return;
      }

      if (!kIsWeb) {
        await _setupLocalNotifications();
      }

      _setupListeners();

      final token = await _getToken();

      if (token != null && token.isNotEmpty) {
        await _sendTokenToBackend(token);
      }
    } catch (e) {
      if (kDebugMode) {
        print('PUSH INIT ERROR: $e');
      }
    }
  }

  static void _setupListeners() {
    if (_listenersReady) {
      return;
    }

    FirebaseMessaging.onMessage.listen((RemoteMessage message) {
      if (!kIsWeb) {
        _showForegroundNotification(message);
      }
    });

    _messaging.onTokenRefresh.listen((token) async {
      await _sendTokenToBackend(token);
    });

    _listenersReady = true;
  }

  static Future<String?> _getToken() async {
    if (kIsWeb) {
      return _messaging.getToken(
        vapidKey: _webVapidKey,
      );
    }

    return _messaging.getToken();
  }

  static Future<void> _sendTokenToBackend(String token) async {
    try {
      final platform = kIsWeb ? 'web' : defaultTargetPlatform.name;

      await ApiClient.post(
        '/push/token',
        {
          'token': token,
          'platform': platform,
        },
      );

      if (kDebugMode) {
        print('PUSH TOKEN REGISTERED: $platform');
      }
    } catch (e) {
      if (kDebugMode) {
        print('PUSH TOKEN SEND ERROR: $e');
      }
    }
  }

  static Future<void> deleteTokenFromBackend() async {
    try {
      final token = await _getToken();

      if (token == null || token.isEmpty) {
        return;
      }

      await ApiClient.post(
        '/push/token/delete',
        {
          'token': token,
        },
      );
    } catch (e) {
      if (kDebugMode) {
        print('PUSH TOKEN DELETE ERROR: $e');
      }
    }
  }

  static Future<void> _setupLocalNotifications() async {
    if (_localNotificationsReady) {
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