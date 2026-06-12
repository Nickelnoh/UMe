import 'package:flutter/material.dart';

import 'app.dart';
import 'core/onesignal_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await OneSignalService.initialize();

  runApp(const MessengerApp());
}