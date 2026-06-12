import 'package:flutter/material.dart';

import '../../core/api_client.dart';
import '../../core/secure_storage.dart';
import '../../widgets/top_notification.dart';
import '../chats/chats_screen.dart';
import 'register_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  bool _loading = false;
  bool _obscurePassword = true;

  static const _green = Color(0xFF075E54);
  static const _lightGreen = Color(0xFF128C7E);

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    final username = _usernameController.text.trim();
    final password = _passwordController.text;

    if (username.isEmpty || password.isEmpty) {
      _showError('Введите username и пароль');
      return;
    }

    setState(() => _loading = true);

    try {
      final response = await ApiClient.post(
        '/auth/login',
        {
          'username': username,
          'password': password,
        },
        withAuth: false,
      );

      if (response is! Map) {
        throw Exception('Некорректный ответ сервера');
      }

      final accessToken = response['access_token']?.toString();
      final refreshToken = response['refresh_token']?.toString();

      if (accessToken == null || accessToken.isEmpty) {
        throw Exception('Сервер не вернул access_token');
      }

      if (refreshToken == null || refreshToken.isEmpty) {
        throw Exception('Сервер не вернул refresh_token');
      }

      await SecureStorage.saveTokens(
        accessToken: accessToken,
        refreshToken: refreshToken,
      );

      if (!mounted) return;

      TopNotification.success(context, message: 'Вы вошли в аккаунт');

      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const ChatsScreen()),
        (_) => false,
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  String _cleanError(Object e) {
    var text = e.toString().replaceFirst('Exception: ', '');

    if (text.contains('Failed to fetch')) return 'Не удалось подключиться к серверу';
    if (text.contains('TimeoutException')) return 'Сервер не ответил вовремя';
    if (text.contains('Invalid username or password')) return 'Неверный username или пароль';

    return text;
  }

  void _showError(String message) {
    if (!mounted) return;
    TopNotification.error(context, message: message);
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF0B141A) : const Color(0xFFECE5DD),
      body: SafeArea(
        child: Column(
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.fromLTRB(24, 28, 24, 34),
              decoration: const BoxDecoration(
                color: _green,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 54,
                        height: 54,
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.16),
                          shape: BoxShape.circle,
                        ),
                        child: const Icon(Icons.chat_rounded, color: Colors.white, size: 30),
                      ),
                      const SizedBox(width: 14),
                      const Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'UMe',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 30,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                            SizedBox(height: 2),
                            Text(
                              'Private messenger',
                              style: TextStyle(color: Color(0xFFDCEFEA), fontWeight: FontWeight.w600),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 28),
                  const Text(
                    'Вход в аккаунт',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 22,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Введите данные, чтобы открыть чаты',
                    style: TextStyle(
                      color: Colors.white.withValues(alpha: 0.78),
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(18, 22, 18, 28),
                children: [
                  Card(
                    margin: EdgeInsets.zero,
                    color: isDark ? const Color(0xFF1F2C34) : Colors.white,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                    child: Padding(
                      padding: const EdgeInsets.all(18),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          TextField(
                            controller: _usernameController,
                            enabled: !_loading,
                            textInputAction: TextInputAction.next,
                            decoration: const InputDecoration(
                              labelText: 'Username',
                              prefixIcon: Icon(Icons.alternate_email_rounded),
                            ),
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _passwordController,
                            enabled: !_loading,
                            obscureText: _obscurePassword,
                            onSubmitted: (_) => _loading ? null : _login(),
                            decoration: InputDecoration(
                              labelText: 'Пароль',
                              prefixIcon: const Icon(Icons.lock_outline_rounded),
                              suffixIcon: IconButton(
                                onPressed: _loading
                                    ? null
                                    : () => setState(() => _obscurePassword = !_obscurePassword),
                                icon: Icon(
                                  _obscurePassword ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                                ),
                              ),
                            ),
                          ),
                          const SizedBox(height: 18),
                          FilledButton(
                            onPressed: _loading ? null : _login,
                            style: FilledButton.styleFrom(
                              backgroundColor: _green,
                              padding: const EdgeInsets.symmetric(vertical: 14),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                            ),
                            child: _loading
                                ? const SizedBox(
                                    width: 22,
                                    height: 22,
                                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                                  )
                                : const Text('ВОЙТИ', style: TextStyle(fontWeight: FontWeight.w800)),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  Center(
                    child: TextButton(
                      onPressed: _loading
                          ? null
                          : () {
                              Navigator.of(context).push(
                                MaterialPageRoute(builder: (_) => const RegisterScreen()),
                              );
                            },
                      child: const Text(
                        'Создать новый аккаунт',
                        style: TextStyle(color: _lightGreen, fontWeight: FontWeight.w800),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
