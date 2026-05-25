import 'package:flutter/material.dart';

import 'core/secure_storage.dart';
import 'screens/auth/login_screen.dart';
import 'screens/chats/chats_screen.dart';
import 'screens/settings/settings_screen.dart';

final ValueNotifier<ThemeMode> themeModeNotifier = ValueNotifier(
  ThemeMode.system,
);

class MessengerApp extends StatelessWidget {
  const MessengerApp({super.key});

  Future<bool> _hasToken() async {
    final token = await SecureStorage.getAccessToken();
    return token != null && token.isNotEmpty;
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: themeModeNotifier,
      builder: (context, mode, _) {
        return MaterialApp(
          debugShowCheckedModeBanner: false,
          title: 'UMe Messenger',
          themeMode: mode,
          theme: ThemeData(
            colorScheme: ColorScheme.fromSeed(
              seedColor: Colors.indigo,
            ),
            useMaterial3: true,
          ),
          darkTheme: ThemeData(
            colorScheme: ColorScheme.fromSeed(
              seedColor: Colors.indigo,
              brightness: Brightness.dark,
            ),
            useMaterial3: true,
          ),
          routes: {
            '/login': (_) => const LoginScreen(),
            '/chats': (_) => const ChatsScreen(),
            '/settings': (_) => const SettingsScreen(),
          },
          home: FutureBuilder<bool>(
            future: _hasToken(),
            builder: (context, snapshot) {
              if (!snapshot.hasData) {
                return const Scaffold(
                  body: Center(
                    child: CircularProgressIndicator(),
                  ),
                );
              }

              if (snapshot.data == true) {
                return const ChatsScreen();
              }

              return const LoginScreen();
            },
          ),
        );
      },
    );
  }
}