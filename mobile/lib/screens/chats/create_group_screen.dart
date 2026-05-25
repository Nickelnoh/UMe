import 'dart:async';

import 'package:flutter/material.dart';

import '../../core/api_client.dart';
import '../../widgets/top_notification.dart';

class CreateGroupScreen extends StatefulWidget {
  const CreateGroupScreen({super.key});

  @override
  State<CreateGroupScreen> createState() => _CreateGroupScreenState();
}

class _CreateGroupScreenState extends State<CreateGroupScreen> {
  final _titleController = TextEditingController();
  final _searchController = TextEditingController();

  Timer? _debounce;

  bool _searching = false;
  bool _creating = false;

  List<dynamic> _results = [];
  final Map<String, Map<String, dynamic>> _selected = {};

  @override
  void dispose() {
    _debounce?.cancel();
    _titleController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  void _onSearchChanged(String value) {
    _debounce?.cancel();
    _debounce = Timer(
      const Duration(milliseconds: 350),
      () => _search(value),
    );
  }

  Future<void> _search(String value) async {
    final query = value.trim();

    if (query.length < 2) {
      if (!mounted) return;
      setState(() => _results = []);
      return;
    }

    setState(() => _searching = true);

    try {
      final result = await ApiClient.get(
        '/users/search?q=${Uri.encodeQueryComponent(query)}',
      );

      if (!mounted) return;

      setState(() {
        _results = result is List ? result : [];
      });
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _searching = false);
      }
    }
  }

  void _toggleUser(Map<String, dynamic> user) {
    final id = user['id']?.toString();
    if (id == null || id.isEmpty) return;

    setState(() {
      if (_selected.containsKey(id)) {
        _selected.remove(id);
      } else {
        _selected[id] = user;
      }
    });
  }

  Future<void> _createGroup() async {
    final title = _titleController.text.trim();

    if (title.isEmpty) {
      _showError('Введите название группы');
      return;
    }

    if (_selected.isEmpty) {
      _showError('Выберите хотя бы одного участника');
      return;
    }

    setState(() => _creating = true);

    try {
      final response = await ApiClient.post(
        '/chats/group',
        {
          'title': title,
          'member_user_ids': _selected.keys.toList(),
        },
      );

      if (!mounted) return;

      TopNotification.success(
        context,
        message: 'Группа создана',
      );

      Navigator.of(context).pop(
        response is Map
            ? Map<String, dynamic>.from(response)
            : <String, dynamic>{},
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _creating = false);
      }
    }
  }

  String _userTitle(Map<String, dynamic> user) {
    final displayName = user['display_name']?.toString().trim();
    if (displayName != null && displayName.isNotEmpty) return displayName;

    final nickname = user['nickname']?.toString().trim();
    if (nickname != null && nickname.isNotEmpty) return nickname;

    return user['username']?.toString() ?? 'Пользователь';
  }

  String _cleanError(Object e) {
    var text = e.toString().replaceFirst('Exception: ', '');

    if (text.contains('Failed to fetch')) {
      return 'Не удалось подключиться к серверу';
    }

    if (text.contains('TimeoutException')) {
      return 'Сервер не ответил вовремя';
    }

    if (text.contains('Select at least one member')) {
      return 'Выберите хотя бы одного участника';
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

  @override
  Widget build(BuildContext context) {
    final accent = Theme.of(context).colorScheme.primary;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Новая группа'),
        actions: [
          TextButton(
            onPressed: _creating ? null : _createGroup,
            child: _creating
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Text('Создать'),
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
          children: [
            TextField(
              controller: _titleController,
              enabled: !_creating,
              textInputAction: TextInputAction.next,
              decoration: const InputDecoration(
                labelText: 'Название группы',
                prefixIcon: Icon(Icons.groups_2_outlined),
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            if (_selected.isNotEmpty) ...[
              Text(
                'Участники: ${_selected.length}',
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _selected.entries.map((entry) {
                  final user = entry.value;
                  final title = _userTitle(user);
                  final avatarUrl = user['avatar_url']?.toString();

                  return InputChip(
                    avatar: CircleAvatar(
                      backgroundColor: accent.withValues(alpha: 0.15),
                      backgroundImage: avatarUrl == null || avatarUrl.isEmpty
                          ? null
                          : NetworkImage(ApiClient.absoluteUrl(avatarUrl)),
                      child: avatarUrl == null || avatarUrl.isEmpty
                          ? Text(title.characters.first.toUpperCase())
                          : null,
                    ),
                    label: Text(title),
                    onDeleted: _creating
                        ? null
                        : () {
                            setState(() => _selected.remove(entry.key));
                          },
                  );
                }).toList(),
              ),
              const SizedBox(height: 18),
            ],
            TextField(
              controller: _searchController,
              enabled: !_creating,
              onChanged: _onSearchChanged,
              decoration: InputDecoration(
                labelText: 'Найти пользователей',
                hintText: 'Username, никнейм или имя',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searching
                    ? const Padding(
                        padding: EdgeInsets.all(14),
                        child: SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                      )
                    : null,
                border: const OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            if (_results.isEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 64),
                child: Center(
                  child: Text(
                    _searchController.text.trim().length < 2
                        ? 'Введите минимум 2 символа'
                        : 'Ничего не найдено',
                  ),
                ),
              )
            else
              ..._results.map((raw) {
                final user = Map<String, dynamic>.from(raw as Map);
                final id = user['id']?.toString() ?? '';
                final selected = _selected.containsKey(id);
                final title = _userTitle(user);
                final username = user['username']?.toString() ?? '';
                final avatarUrl = user['avatar_url']?.toString();

                return Card(
                  child: ListTile(
                    onTap: _creating ? null : () => _toggleUser(user),
                    leading: CircleAvatar(
                      backgroundColor: accent.withValues(alpha: 0.15),
                      backgroundImage: avatarUrl == null || avatarUrl.isEmpty
                          ? null
                          : NetworkImage(ApiClient.absoluteUrl(avatarUrl)),
                      child: avatarUrl == null || avatarUrl.isEmpty
                          ? Text(title.characters.first.toUpperCase())
                          : null,
                    ),
                    title: Text(title),
                    subtitle: username.isEmpty ? null : Text('@$username'),
                    trailing: Icon(
                      selected
                          ? Icons.check_circle
                          : Icons.add_circle_outline,
                      color: selected ? accent : null,
                    ),
                  ),
                );
              }),
          ],
        ),
      ),
    );
  }
}
