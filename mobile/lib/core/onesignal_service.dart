import 'package:flutter/foundation.dart';
import 'package:onesignal_flutter/onesignal_flutter.dart';

class OneSignalService {
  static const String appId = '960132c6-2a76-4a92-9ec7-4ad3a7150fbf';

  static bool _initialized = false;

  static Future<void> initialize() async {
    if (_initialized) return;

    OneSignal.Debug.setLogLevel(OSLogLevel.verbose);
    OneSignal.initialize(appId);

    _initialized = true;

    if (kDebugMode) {
      print('ONESIGNAL INIT DONE');
    }
  }

  static Future<void> loginUser(String userId) async {
    await initialize();

    OneSignal.login(userId);

    if (kDebugMode) {
      print('ONESIGNAL LOGIN USER: $userId');
    }
  }

  static Future<void> requestPermission() async {
    await initialize();

    final accepted = await OneSignal.Notifications.requestPermission(true);

    if (kDebugMode) {
      print('ONESIGNAL PERMISSION ACCEPTED: $accepted');
    }
  }

  static Future<void> logoutUser() async {
    await initialize();

    OneSignal.logout();

    if (kDebugMode) {
      print('ONESIGNAL LOGOUT');
    }
  }
}