import 'package:flutter/material.dart';

import '../../core/api_client.dart';
import '../../core/secure_storage.dart';
import '../../widgets/top_notification.dart';
import '../chats/chats_screen.dart';

class RegisterScreen extends StatefulWidget {
  const RegisterScreen({super.key});

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final _usernameController = TextEditingController();
  final _nicknameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _passwordRepeatController = TextEditingController();

  bool _loading = false;
  bool _obscurePassword = true;
  bool _obscurePasswordRepeat = true;

  static const _green = Color(0xFF075E54);
  static const _lightGreen = Color(0xFF128C7E);

  @override
  void dispose() {
    _usernameController.dispose();
    _nicknameController.dispose();
    _passwordController.dispose();
    _passwordRepeatController.dispose();
    super.dispose();
  }

  Future<void> _register() async {
    final username = _usernameController.text.trim();
    final nickname = _nicknameController.text.trim();
    final password = _passwordController.text;
    final passwordRepeat = _passwordRepeatController.text;

    if (username.isEmpty || nickname.isEmpty || password.isEmpty) {
      _showError('Заполните все поля');
      return;
    }

    if (username.length < 3) {
      _showError('Username должен быть минимум 3 символа');
      return;
    }

    if (nickname.length < 2) {
      _showError('Никнейм должен быть минимум 2 символа');
      return;
    }

    if (password.length < 6) {
      _showError('Пароль должен быть минимум 6 символов');
      return;
    }

    if (password != passwordRepeat) {
      _showError('Пароли не совпадают');
      return;
    }

    setState(() => _loading = true);

    try {
      final response = await ApiClient.post(
        '/auth/register',
        {
          'username': username,
          'nickname': nickname,
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

      TopNotification.success(context, message: 'Аккаунт создан');

      Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const ChatsScreen()),
        (_) => false,
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  String _cleanError(Object e) {
    var text = e.toString().replaceFirst('Exception: ', '');
    if (text.contains('Username or nickname already exists')) return 'Username или никнейм уже занят';
    if (text.contains('Failed to fetch')) return 'Не удалось подключиться к серверу';
    if (text.contains('TimeoutException')) return 'Сервер не ответил вовремя';
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
      appBar: AppBar(
        title: const Text('Новый аккаунт'),
        backgroundColor: _green,
        foregroundColor: Colors.white,
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(18, 18, 18, 28),
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
                    const Text(
                      'Создание UMe',
                      style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Заполните данные аккаунта. Номер телефона не нужен.',
                      style: TextStyle(color: Color(0xFF667781), fontWeight: FontWeight.w500),
                    ),
                    const SizedBox(height: 18),
                    TextField(
                      controller: _usernameController,
                      enabled: !_loading,
                      decoration: const InputDecoration(
                        labelText: 'Username',
                        prefixIcon: Icon(Icons.alternate_email_rounded),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _nicknameController,
                      enabled: !_loading,
                      decoration: const InputDecoration(
                        labelText: 'Имя в чатах',
                        prefixIcon: Icon(Icons.person_outline_rounded),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _passwordController,
                      enabled: !_loading,
                      obscureText: _obscurePassword,
                      decoration: InputDecoration(
                        labelText: 'Пароль',
                        prefixIcon: const Icon(Icons.lock_outline_rounded),
                        suffixIcon: IconButton(
                          onPressed: _loading
                              ? null
                              : () => setState(() => _obscurePassword = !_obscurePassword),
                          icon: Icon(_obscurePassword ? Icons.visibility_outlined : Icons.visibility_off_outlined),
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _passwordRepeatController,
                      enabled: !_loading,
                      obscureText: _obscurePasswordRepeat,
                      onSubmitted: (_) => _loading ? null : _register(),
                      decoration: InputDecoration(
                        labelText: 'Повтор пароля',
                        prefixIcon: const Icon(Icons.lock_reset_rounded),
                        suffixIcon: IconButton(
                          onPressed: _loading
                              ? null
                              : () => setState(() => _obscurePasswordRepeat = !_obscurePasswordRepeat),
                          icon: Icon(_obscurePasswordRepeat ? Icons.visibility_outlined : Icons.visibility_off_outlined),
                        ),
                      ),
                    ),
                    const SizedBox(height: 18),
                    FilledButton(
                      onPressed: _loading ? null : _register,
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
                          : const Text('СОЗДАТЬ', style: TextStyle(fontWeight: FontWeight.w800)),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 14),
            Center(
              child: TextButton(
                onPressed: _loading ? null : () => Navigator.of(context).pop(),
                child: const Text(
                  'Уже есть аккаунт',
                  style: TextStyle(color: _lightGreen, fontWeight: FontWeight.w800),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
