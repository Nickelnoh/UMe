import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'core/push_service.dart';
import 'core/secure_storage.dart';
import 'screens/auth/login_screen.dart';
import 'screens/chats/chats_screen.dart';
import 'screens/settings/settings_screen.dart';

final ValueNotifier<ThemeMode> themeModeNotifier = ValueNotifier(
  ThemeMode.system,
);

class MessengerApp extends StatefulWidget {
  const MessengerApp({super.key});

  @override
  State<MessengerApp> createState() => _MessengerAppState();
}

class _MessengerAppState extends State<MessengerApp> {
  Future<bool>? _hasTokenFuture;
  bool _showNotificationBanner = false;
  bool _checkingNotifications = true;

  @override
  void initState() {
    super.initState();
    _hasTokenFuture = _hasToken();
    _checkNotificationStateOnOpen();
  }

  Future<bool> _hasToken() async {
    final token = await SecureStorage.getAccessToken();
    return token != null && token.isNotEmpty;
  }

  Future<void> _checkNotificationStateOnOpen() async {
    try {
      final hasToken = await _hasToken();

      if (!hasToken) {
        if (!mounted) return;

        setState(() {
          _showNotificationBanner = false;
          _checkingNotifications = false;
        });

        return;
      }

      final shouldShowBanner = await PushService.shouldShowPermissionBanner();

      if (!mounted) return;

      setState(() {
        _showNotificationBanner = shouldShowBanner;
        _checkingNotifications = false;
      });

      if (!shouldShowBanner) {
        await PushService.registerIfPermissionAlreadyGranted();
      }
    } catch (e) {
      if (kDebugMode) {
        print('PUSH CHECK ON OPEN ERROR: $e');
      }

      if (!mounted) return;

      setState(() {
        _showNotificationBanner = false;
        _checkingNotifications = false;
      });
    }
  }

  Future<void> _enableNotifications() async {
    try {
      await PushService.initializeAndRegister();

      final shouldShowBanner = await PushService.shouldShowPermissionBanner();

      if (!mounted) return;

      setState(() {
        _showNotificationBanner = shouldShowBanner;
      });
    } catch (e) {
      if (kDebugMode) {
        print('PUSH ENABLE ERROR: $e');
      }
    }
  }

  void _hideNotificationBanner() {
    setState(() {
      _showNotificationBanner = false;
    });
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
          builder: (context, child) {
            return Stack(
              children: [
                child ?? const SizedBox.shrink(),
                if (!_checkingNotifications && _showNotificationBanner)
                  _NotificationPermissionBanner(
                    onEnable: _enableNotifications,
                    onClose: _hideNotificationBanner,
                  ),
              ],
            );
          },
          home: FutureBuilder<bool>(
            future: _hasTokenFuture,
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

class _NotificationPermissionBanner extends StatelessWidget {
  final Future<void> Function() onEnable;
  final VoidCallback onClose;

  const _NotificationPermissionBanner({
    required this.onEnable,
    required this.onClose,
  });

  @override
  Widget build(BuildContext context) {
    final topPadding = MediaQuery.of(context).padding.top;

    return Positioned(
      top: topPadding + 12,
      left: 12,
      right: 12,
      child: Material(
        color: Colors.transparent,
        child: SafeArea(
          bottom: false,
          child: Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: const Color(0xFF151826).withValues(alpha: 0.96),
              borderRadius: BorderRadius.circular(22),
              border: Border.all(
                color: const Color(0xFF8EA0FF).withValues(alpha: 0.35),
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.35),
                  blurRadius: 24,
                  offset: const Offset(0, 12),
                ),
              ],
            ),
            child: Row(
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: const Color(0xFF8EA0FF).withValues(alpha: 0.16),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: const Icon(
                    Icons.notifications_active_outlined,
                    color: Color(0xFFB6C1FF),
                  ),
                ),
                const SizedBox(width: 12),
                const Expanded(
                  child: DefaultTextStyle(
                    style: TextStyle(
                      color: Colors.white,
                      decoration: TextDecoration.none,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          'Включить уведомления?',
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        SizedBox(height: 3),
                        Text(
                          'Нажмите кнопку, чтобы получать сообщения даже вне вкладки.',
                          style: TextStyle(
                            fontSize: 12,
                            color: Color(0xFFC8CEE8),
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                TextButton(
                  onPressed: onEnable,
                  style: TextButton.styleFrom(
                    foregroundColor: const Color(0xFFCAD3FF),
                  ),
                  child: const Text('Включить'),
                ),
                IconButton(
                  onPressed: onClose,
                  icon: const Icon(Icons.close),
                  color: const Color(0xFFC8CEE8),
                  tooltip: 'Закрыть',
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}