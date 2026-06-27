import 'package:flutter/foundation.dart';
import 'package:onesignal_flutter/onesignal_flutter.dart';

import 'onesignal_web_bridge.dart';

class OneSignalService {
  static const String appId = '960132c6-2a76-4a92-9ec7-4ad3a7150fbf';

  static bool _initialized = false;
  static String? _loggedUserId;

  static Future<void> initialize() async {
    if (_initialized) {
      return;
    }

    try {
      if (kIsWeb) {
        await oneSignalWebInit(appId);
        _initialized = true;

        if (kDebugMode) {
          print('ONESIGNAL WEB INIT DONE');
        }

        return;
      }

      OneSignal.Debug.setLogLevel(OSLogLevel.verbose);

      OneSignal.initialize(appId);

      OneSignal.Notifications.addForegroundWillDisplayListener((event) {
        if (kDebugMode) {
          print('ONESIGNAL FOREGROUND NOTIFICATION: ${event.notification.title}');
        }

        // Показываем уведомление даже когда приложение открыто.
        event.notification.display();
      });

      OneSignal.Notifications.addClickListener((event) {
        if (kDebugMode) {
          print('ONESIGNAL NOTIFICATION CLICKED: ${event.notification.title}');
          print('ONESIGNAL NOTIFICATION DATA: ${event.notification.additionalData}');
        }
      });

      _initialized = true;

      final accepted = await OneSignal.Notifications.requestPermission(true);

      if (kDebugMode) {
        print('ONESIGNAL MOBILE INIT DONE');
        print('ONESIGNAL MOBILE PERMISSION ACCEPTED: $accepted');
      }
    } catch (e, st) {
      if (kDebugMode) {
        print('ONESIGNAL INIT ERROR: $e');
        print(st);
      }
    }
  }

  static Future<void> loginUser(String userId) async {
    await initialize();

    if (userId.trim().isEmpty) {
      if (kDebugMode) {
        print('ONESIGNAL LOGIN SKIPPED: EMPTY USER ID');
      }
      return;
    }

    _loggedUserId = userId;

    try {
      if (kIsWeb) {
        await oneSignalWebLogin(userId);
      } else {
        OneSignal.login(userId);
      }

      if (kDebugMode) {
        print('ONESIGNAL LOGIN USER: $userId');
      }
    } catch (e, st) {
      if (kDebugMode) {
        print('ONESIGNAL LOGIN ERROR: $e');
        print(st);
      }
    }
  }

  static Future<void> requestPermission() async {
    await initialize();

    try {
      if (kIsWeb) {
        final accepted = await oneSignalWebRequestPermission();

        if (kDebugMode) {
          print('ONESIGNAL WEB PERMISSION ACCEPTED: $accepted');
        }

        return;
      }

      final accepted = await OneSignal.Notifications.requestPermission(true);

      if (kDebugMode) {
        print('ONESIGNAL MOBILE PERMISSION ACCEPTED: $accepted');
      }
    } catch (e, st) {
      if (kDebugMode) {
        print('ONESIGNAL PERMISSION ERROR: $e');
        print(st);
      }
    }
  }

  static Future<void> logoutUser() async {
    await initialize();

    try {
      if (kIsWeb) {
        await oneSignalWebLogout();
      } else {
        OneSignal.logout();
      }

      _loggedUserId = null;

      if (kDebugMode) {
        print('ONESIGNAL LOGOUT');
      }
    } catch (e, st) {
      if (kDebugMode) {
        print('ONESIGNAL LOGOUT ERROR: $e');
        print(st);
      }
    }
  }

  static String? get loggedUserId => _loggedUserId;
}