import 'package:flutter/material.dart';

import 'core/secure_storage.dart';
import 'screens/auth/login_screen.dart';
import 'screens/chats/chats_screen.dart';
import 'screens/settings/settings_screen.dart';

const Color umeDefaultGreen = Color(0xFF075E54);
const Color umeDefaultLightGreen = Color(0xFF128C7E);

final ValueNotifier<ThemeMode> themeModeNotifier = ValueNotifier(
  ThemeMode.system,
);

final ValueNotifier<Color> accentColorNotifier = ValueNotifier(
  umeDefaultGreen,
);

Color parseUmeAccentColor(String value) {
  final text = value.trim();

  if (text.startsWith('#')) {
    final hex = text.substring(1);

    if (hex.length == 6 || hex.length == 8) {
      final parsed = int.tryParse(hex, radix: 16);

      if (parsed != null) {
        if (hex.length == 6) return Color(0xFF000000 | parsed);
        return Color(parsed);
      }
    }
  }

  switch (text) {
    case 'green':
      return umeDefaultGreen;
    case 'purple':
      return Colors.purple;
    case 'orange':
      return Colors.orange;
    case 'pink':
      return Colors.pink;
    case 'blue':
      return Colors.blue;
    default:
      return umeDefaultGreen;
  }
}

ThemeMode parseUmeThemeMode(String value) {
  switch (value) {
    case 'light':
      return ThemeMode.light;
    case 'dark':
      return ThemeMode.dark;
    case 'system':
    default:
      return ThemeMode.system;
  }
}

class MessengerApp extends StatefulWidget {
  const MessengerApp({super.key});

  @override
  State<MessengerApp> createState() => _MessengerAppState();
}

class _MessengerAppState extends State<MessengerApp> {
  Future<bool>? _hasTokenFuture;

  @override
  void initState() {
    super.initState();
    _hasTokenFuture = _hasToken();
  }

  Future<bool> _hasToken() async {
    final token = await SecureStorage.getAccessToken();
    return token != null && token.isNotEmpty;
  }

  ThemeData _theme(Brightness brightness, Color accent) {
    final isDark = brightness == Brightness.dark;
    final secondary = HSLColor.fromColor(accent)
        .withLightness(isDark ? 0.46 : 0.40)
        .withSaturation(0.62)
        .toColor();

    final colorScheme = ColorScheme.fromSeed(
      seedColor: accent,
      brightness: brightness,
      primary: accent,
      secondary: secondary,
      surface: isDark ? const Color(0xFF111B21) : Colors.white,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: colorScheme,
      scaffoldBackgroundColor:
          isDark ? const Color(0xFF0B141A) : const Color(0xFFF7F7F7),
      appBarTheme: AppBarTheme(
        backgroundColor: accent,
        foregroundColor: Colors.white,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        titleTextStyle: const TextStyle(
          color: Colors.white,
          fontSize: 20,
          fontWeight: FontWeight.w700,
        ),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: accent,
        foregroundColor: Colors.white,
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: accent,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: isDark ? const Color(0xFF1F2C34) : Colors.white,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: Color(0xFFD9D9D9)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(
            color: isDark ? const Color(0xFF2A3942) : const Color(0xFFD9D9D9),
          ),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: accent, width: 1.8),
        ),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: isDark ? const Color(0xFF1F2C34) : Colors.white,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
      dividerColor: isDark ? const Color(0xFF2A3942) : const Color(0xFFEAEAEA),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: themeModeNotifier,
      builder: (context, mode, _) {
        return ValueListenableBuilder<Color>(
          valueListenable: accentColorNotifier,
          builder: (context, accent, _) {
            return MaterialApp(
              debugShowCheckedModeBanner: false,
              title: 'UMe Messenger',
              themeMode: mode,
              theme: _theme(Brightness.light, accent),
              darkTheme: _theme(Brightness.dark, accent),
              routes: {
                '/login': (_) => const LoginScreen(),
                '/chats': (_) => const ChatsScreen(),
                '/settings': (_) => const SettingsScreen(),
              },
              home: FutureBuilder<bool>(
                future: _hasTokenFuture,
                builder: (context, snapshot) {
                  if (!snapshot.hasData) {
                    return const Scaffold(
                      body: Center(child: CircularProgressIndicator()),
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
      },
    );
  }
}
