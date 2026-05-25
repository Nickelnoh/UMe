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

      TopNotification.success(
        context,
        message: 'Аккаунт создан',
      );

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
    var text = e.toString();
    text = text.replaceFirst('Exception: ', '');

    if (text.contains('Username or nickname already exists')) {
      return 'Такой username или никнейм уже занят';
    }

    if (text.contains('Failed to fetch')) {
      return 'Не удалось подключиться к серверу';
    }

    if (text.contains('TimeoutException')) {
      return 'Сервер не ответил вовремя';
    }

    if (text.contains('422')) {
      return 'Некорректные данные регистрации';
    }

    return text;
  }

  void _showError(String message) {
    if (!mounted) return;

    TopNotification.error(
      context,
      message: message,
    );
  }

  void _openLogin() {
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Регистрация'),
      ),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(24, 24, 24, 32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 430),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.person_add_alt_1_outlined,
                    size: 72,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(height: 20),
                  Text(
                    'Создать аккаунт',
                    style: Theme.of(context).textTheme.headlineMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Зарегистрируйтесь по username и паролю',
                    style: Theme.of(context).textTheme.bodyMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 32),
                  TextField(
                    controller: _usernameController,
                    enabled: !_loading,
                    textInputAction: TextInputAction.next,
                    decoration: const InputDecoration(
                      labelText: 'Username',
                      prefixIcon: Icon(Icons.person_outline),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _nicknameController,
                    enabled: !_loading,
                    textInputAction: TextInputAction.next,
                    decoration: const InputDecoration(
                      labelText: 'Никнейм',
                      prefixIcon: Icon(Icons.badge_outlined),
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _passwordController,
                    enabled: !_loading,
                    obscureText: _obscurePassword,
                    textInputAction: TextInputAction.next,
                    decoration: InputDecoration(
                      labelText: 'Пароль',
                      prefixIcon: const Icon(Icons.password),
                      border: const OutlineInputBorder(),
                      suffixIcon: IconButton(
                        onPressed: _loading
                            ? null
                            : () {
                                setState(() {
                                  _obscurePassword = !_obscurePassword;
                                });
                              },
                        icon: Icon(
                          _obscurePassword
                              ? Icons.visibility
                              : Icons.visibility_off,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _passwordRepeatController,
                    enabled: !_loading,
                    obscureText: _obscurePasswordRepeat,
                    textInputAction: TextInputAction.done,
                    onSubmitted: (_) {
                      if (!_loading) _register();
                    },
                    decoration: InputDecoration(
                      labelText: 'Повторите пароль',
                      prefixIcon: const Icon(Icons.lock_outline),
                      border: const OutlineInputBorder(),
                      suffixIcon: IconButton(
                        onPressed: _loading
                            ? null
                            : () {
                                setState(() {
                                  _obscurePasswordRepeat =
                                      !_obscurePasswordRepeat;
                                });
                              },
                        icon: Icon(
                          _obscurePasswordRepeat
                              ? Icons.visibility
                              : Icons.visibility_off,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  SizedBox(
                    width: double.infinity,
                    height: 48,
                    child: FilledButton(
                      onPressed: _loading ? null : _register,
                      child: _loading
                          ? const SizedBox(
                              width: 22,
                              height: 22,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Text('Создать аккаунт'),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextButton(
                    onPressed: _loading ? null : _openLogin,
                    child: const Text('Уже есть аккаунт'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}