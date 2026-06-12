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
    const green = Color(0xFF075E54);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF0B141A) : const Color(0xFFECE5DD),
      appBar: AppBar(
        title: const Text('Новая группа'),
        backgroundColor: green,
        foregroundColor: Colors.white,
        actions: [
          TextButton(
            onPressed: _creating ? null : _createGroup,
            child: _creating
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                  )
                : const Text(
                    'ГОТОВО',
                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.w900),
                  ),
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: EdgeInsets.zero,
          children: [
            Container(
              color: green,
              padding: const EdgeInsets.fromLTRB(18, 4, 18, 18),
              child: Row(
                children: [
                  const CircleAvatar(
                    radius: 31,
                    backgroundColor: Colors.white,
                    foregroundColor: green,
                    child: Icon(Icons.groups_rounded, size: 33),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: TextField(
                      controller: _titleController,
                      enabled: !_creating,
                      style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w800),
                      cursorColor: Colors.white,
                      decoration: InputDecoration(
                        hintText: 'Название группы',
                        hintStyle: TextStyle(color: Colors.white.withValues(alpha: 0.72)),
                        filled: false,
                        enabledBorder: UnderlineInputBorder(
                          borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.45)),
                        ),
                        focusedBorder: const UnderlineInputBorder(
                          borderSide: BorderSide(color: Colors.white, width: 2),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            if (_selected.isNotEmpty)
              Container(
                color: isDark ? const Color(0xFF1F2C34) : Colors.white,
                padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Участники: ${_selected.length}',
                      style: const TextStyle(color: Color(0xFF075E54), fontWeight: FontWeight.w900),
                    ),
                    const SizedBox(height: 10),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: _selected.entries.map((entry) {
                        final user = entry.value;
                        final title = _userTitle(user);
                        final avatarUrl = user['avatar_url']?.toString();

                        return InputChip(
                          backgroundColor: const Color(0xFFE7F6F2),
                          avatar: CircleAvatar(
                            backgroundColor: green,
                            foregroundColor: Colors.white,
                            backgroundImage: avatarUrl == null || avatarUrl.isEmpty
                                ? null
                                : NetworkImage(ApiClient.absoluteUrl(avatarUrl)),
                            child: avatarUrl == null || avatarUrl.isEmpty
                                ? Text(title.characters.first.toUpperCase())
                                : null,
                          ),
                          label: Text(title),
                          onDeleted: _creating ? null : () => setState(() => _selected.remove(entry.key)),
                        );
                      }).toList(),
                    ),
                  ],
                ),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 12, 12, 8),
              child: TextField(
                controller: _searchController,
                enabled: !_creating,
                onChanged: _onSearchChanged,
                decoration: InputDecoration(
                  labelText: 'Найти пользователей',
                  hintText: 'Username, никнейм или имя',
                  prefixIcon: const Icon(Icons.search_rounded),
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
                ),
              ),
            ),
            if (_results.isEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 72),
                child: Center(
                  child: Text(
                    _searchController.text.trim().length < 2 ? 'Введите минимум 2 символа' : 'Ничего не найдено',
                    style: const TextStyle(color: Color(0xFF667781), fontWeight: FontWeight.w600),
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

                return Material(
                  color: isDark ? const Color(0xFF0B141A) : Colors.white,
                  child: InkWell(
                    onTap: _creating ? null : () => _toggleUser(user),
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(14, 9, 12, 0),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 24,
                            backgroundColor: const Color(0xFFE2F0EC),
                            foregroundColor: green,
                            backgroundImage: avatarUrl == null || avatarUrl.isEmpty
                                ? null
                                : NetworkImage(ApiClient.absoluteUrl(avatarUrl)),
                            child: avatarUrl == null || avatarUrl.isEmpty
                                ? Text(title.characters.first.toUpperCase(), style: const TextStyle(fontWeight: FontWeight.w900))
                                : null,
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Container(
                              padding: const EdgeInsets.only(bottom: 10),
                              decoration: const BoxDecoration(
                                border: Border(bottom: BorderSide(color: Color(0xFFEAEAEA))),
                              ),
                              child: Row(
                                children: [
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      children: [
                                        Text(title, style: const TextStyle(fontWeight: FontWeight.w900, fontSize: 15.8)),
                                        if (username.isNotEmpty)
                                          Text('@$username', style: const TextStyle(color: Color(0xFF667781))),
                                      ],
                                    ),
                                  ),
                                  Icon(
                                    selected ? Icons.check_circle_rounded : Icons.add_circle_outline_rounded,
                                    color: selected ? green : const Color(0xFF667781),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
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
