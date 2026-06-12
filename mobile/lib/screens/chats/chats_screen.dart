import 'dart:async';

import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_client.dart';
import '../../core/onesignal_service.dart';
import '../../core/secure_storage.dart';
import '../../core/websocket_service.dart';
import '../../widgets/top_notification.dart';
import '../messages/chat_screen.dart';
import 'create_group_screen.dart';
import '../settings/settings_screen.dart';

enum _ChatsTab { chats, requests, groups }

class ChatsScreen extends StatefulWidget {
  const ChatsScreen({super.key});

  @override
  State<ChatsScreen> createState() => _ChatsScreenState();
}

class _ChatsScreenState extends State<ChatsScreen> {
  final _ws = WebSocketService();

  StreamSubscription<Map<String, dynamic>>? _wsSubscription;

  bool _loading = true;
  bool _refreshing = false;
  bool _notificationsEnabled = false;

  String? _myUserId;
  String _myName = '';

  _ChatsTab _selectedTab = _ChatsTab.chats;

  List<dynamic> _chats = [];
  List<dynamic> _incomingRequests = [];
  List<dynamic> _outgoingRequests = [];

  Color get _whatsAppGreen => accentColorNotifier.value;
  Color get _whatsAppFabGreen => accentColorNotifier.value;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    await _loadMe();
    await _loadAll();
    await _connectWebSocket();
  }

  Future<void> _loadMe() async {
    try {
      final me = await ApiClient.get('/me');
      final userId = me['id']?.toString();

      if (userId != null && userId.isNotEmpty) {
        await OneSignalService.loginUser(userId);
      }

      if (!mounted) return;

      setState(() {
        _myUserId = userId;
        _myName = me['display_name']?.toString().trim().isNotEmpty == true
            ? me['display_name'].toString()
            : me['nickname']?.toString().trim().isNotEmpty == true
                ? me['nickname'].toString()
                : me['username']?.toString() ?? '';
      });
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _connectWebSocket() async {
    try {
      await _ws.connect();

      if (!mounted) return;

      _wsSubscription = _ws.events.listen((event) async {
        if (!mounted) return;

        final type = event['type']?.toString();

        if (type == 'chat.created') {
          await _loadChats(silent: true);

          if (!mounted) return;

          final rawChat = event['chat'];
          final chat = rawChat is Map
              ? Map<String, dynamic>.from(rawChat)
              : <String, dynamic>{};

          final title = chat['title']?.toString() ?? 'Новая группа';

          TopNotification.message(
            context,
            title: 'Новый чат',
            message: title,
          );
          return;
        }

        if (type == 'chat.updated' || type == 'chat.members.updated') {
          await _loadChats(silent: true);
          return;
        }

        if (type == 'message.created') {
          final rawMessage = event['message'];
          final message = rawMessage is Map
              ? Map<String, dynamic>.from(rawMessage)
              : <String, dynamic>{};

          final senderId = message['sender_user_id']?.toString();

          await _loadChats(silent: true);

          if (!mounted) return;

          if (senderId != null && senderId != _myUserId) {
            final title = _chatTitleById(event['chat_id']?.toString());
            final text = message['text']?.toString().trim();

            TopNotification.message(
              context,
              title: title.isNotEmpty ? title : 'Новое сообщение',
              message: text != null && text.isNotEmpty
                  ? text
                  : 'Новое вложение',
            );
          }
          return;
        }

        if (type == 'message.updated' || type == 'message.deleted') {
          await _loadChats(silent: true);
          return;
        }

        if (type == 'chat_request.created') {
          await _loadRequests(silent: true);

          if (!mounted) return;

          final rawRequest = event['request'];
          final request = rawRequest is Map
              ? Map<String, dynamic>.from(rawRequest)
              : <String, dynamic>{};

          final requesterName =
              request['requester_name']?.toString().trim().isNotEmpty == true
                  ? request['requester_name'].toString()
                  : request['requester_username']?.toString() ?? 'Пользователь';

          TopNotification.message(
            context,
            title: 'Запрос на чат',
            message: '$requesterName хочет начать чат',
          );
          return;
        }

        if (type == 'chat_request.accepted') {
          await _loadAll(silent: true);

          if (!mounted) return;

          TopNotification.success(
            context,
            message: 'Запрос на чат принят',
          );
          return;
        }

        if (type == 'chat_request.declined') {
          await _loadRequests(silent: true);

          if (!mounted) return;

          TopNotification.info(
            context,
            message: 'Запрос на чат отклонён',
          );
          return;
        }

        if (type == 'chat_request.cancelled') {
          await _loadRequests(silent: true);
          return;
        }

        if (type == 'chat.deleted' || type == 'chat.left') {
          await _loadChats(silent: true);
          return;
        }
      });
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  String _chatTitleById(String? chatId) {
    if (chatId == null) return '';

    for (final item in _chats) {
      final chat = Map<String, dynamic>.from(item as Map);

      if (chat['id']?.toString() == chatId) {
        return chat['title']?.toString() ?? '';
      }
    }

    return '';
  }

  Future<void> _loadAll({bool silent = false}) async {
    if (!silent && mounted) {
      setState(() => _loading = true);
    }

    try {
      await Future.wait([
        _loadChats(silent: true),
        _loadRequests(silent: true),
      ]);
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted && !silent) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _loadChats({bool silent = false}) async {
    if (!silent && mounted) {
      setState(() => _refreshing = true);
    }

    try {
      final result = await ApiClient.get('/chats');

      if (!mounted) return;

      setState(() {
        _chats = result is List ? result : [];
      });
    } catch (e) {
      if (!silent) {
        _showError(_cleanError(e));
      }
    } finally {
      if (mounted && !silent) {
        setState(() => _refreshing = false);
      }
    }
  }

  Future<void> _loadRequests({bool silent = false}) async {
    try {
      final incoming = await ApiClient.get('/chat-requests/incoming');
      final outgoing = await ApiClient.get('/chat-requests/outgoing');

      if (!mounted) return;

      setState(() {
        _incomingRequests = incoming is List ? incoming : [];
        _outgoingRequests = outgoing is List ? outgoing : [];
      });
    } catch (e) {
      if (!silent) {
        _showError(_cleanError(e));
      }
    }
  }

  Future<void> _refresh() async {
    if (_refreshing) return;

    if (mounted) {
      setState(() => _refreshing = true);
    }

    try {
      await _loadMe();
      await _loadAll(silent: false);

      if (!mounted) return;

      TopNotification.success(
        context,
        message: 'Чаты обновлены',
      );
    } finally {
      if (mounted) {
        setState(() => _refreshing = false);
      }
    }
  }

  Future<void> _enablePushNotifications({bool showSuccess = true}) async {
    try {
      if (_myUserId != null && _myUserId!.isNotEmpty) {
        await OneSignalService.loginUser(_myUserId!);
      }

      await OneSignalService.requestPermission();

      if (!mounted) return;

      setState(() => _notificationsEnabled = true);

      if (showSuccess) {
        TopNotification.success(
          context,
          message: 'Уведомления включены',
        );
      }
    } catch (e) {
      if (!mounted) return;

      TopNotification.error(
        context,
        message: 'Ошибка уведомлений: ${_cleanError(e)}',
      );
    }
  }

  Future<void> _logout() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: const Text('Выйти из аккаунта?'),
          content: const Text(
            'Вы выйдете из UMe на этом устройстве. Чтобы вернуться, нужно будет снова войти.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(dialogContext).pop(true),
              style: FilledButton.styleFrom(backgroundColor: _whatsAppGreen),
              child: const Text('Выйти'),
            ),
          ],
        );
      },
    );

    if (confirmed != true) return;

    try {
      try {
        await ApiClient.post('/auth/logout', {});
      } catch (_) {}

      try {
        await OneSignalService.logoutUser();
      } catch (_) {}

      await _wsSubscription?.cancel();
      _ws.dispose();
      await SecureStorage.clear();

      if (!mounted) return;

      Navigator.of(context).pushNamedAndRemoveUntil(
        '/login',
        (route) => false,
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _openSettings() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const SettingsScreen()),
    );

    if (!mounted) return;

    await _loadMe();
    await _loadAll(silent: true);
  }

  Future<void> _openSearchUsers() async {
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (sheetContext) {
        return _UserSearchSheet(
          accent: _whatsAppGreen,
          onRequestSent: () async {
            await _loadRequests(silent: true);

            if (!mounted) return;

            TopNotification.success(
              context,
              message: 'Запрос на чат отправлен',
            );
          },
          onError: (message) {
            if (!mounted) return;

            TopNotification.error(
              context,
              message: message,
            );
          },
        );
      },
    );
  }

  Future<void> _acceptRequest(String requestId) async {
    try {
      final result = await ApiClient.post(
        '/chat-requests/$requestId/accept',
        {},
      );

      await _loadAll(silent: true);

      if (!mounted) return;

      TopNotification.success(
        context,
        message: 'Запрос принят',
      );

      if (result is Map && result['chat'] is Map) {
        final chat = Map<String, dynamic>.from(result['chat'] as Map);
        final chatId = chat['id']?.toString();
        final title = chat['title']?.toString() ?? 'Чат';

        if (chatId != null && chatId.isNotEmpty) {
          _openChat(chatId, title);
        }
      }
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _declineRequest(String requestId) async {
    try {
      await ApiClient.post(
        '/chat-requests/$requestId/decline',
        {},
      );

      await _loadRequests(silent: true);

      if (!mounted) return;

      TopNotification.info(
        context,
        message: 'Запрос отклонён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _cancelRequest(String requestId) async {
    try {
      await ApiClient.post('/chat-requests/$requestId/cancel', {});
      await _loadRequests(silent: true);

      if (!mounted) return;

      TopNotification.info(
        context,
        message: 'Запрос отменён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _confirmDeleteChat(
    String chatId,
    String title, {
    bool isGroup = false,
  }) async {
    if (chatId.isEmpty) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: Text(isGroup ? 'Удалить группу?' : 'Удалить чат?'),
          content: Text(
            isGroup
                ? 'Группа "$title" исчезнет из вашего списка чатов. Для остальных участников она останется.'
                : 'Чат "$title" будет скрыт из вашего списка.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(dialogContext).pop(true),
              style: FilledButton.styleFrom(
                backgroundColor: const Color(0xFFD32F2F),
              ),
              child: const Text('Удалить'),
            ),
          ],
        );
      },
    );

    if (confirmed != true) return;

    await _deleteChat(chatId);
  }

  Future<void> _deleteChat(String chatId) async {
    try {
      await ApiClient.post('/chats/$chatId/delete', {});
      await _loadChats(silent: true);

      if (!mounted) return;

      TopNotification.info(
        context,
        message: 'Чат удалён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _openCreateGroup() async {
    final result = await Navigator.of(context).push<Map<String, dynamic>>(
      MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
    );

    if (!mounted) return;

    await _loadChats(silent: true);

    if (result == null) return;

    final chatId = result['id']?.toString();
    final title = result['title']?.toString() ?? 'Группа';

    if (chatId != null && chatId.isNotEmpty) {
      _openChat(chatId, title, isGroup: true);
    }
  }

  void _openChat(
    String chatId,
    String title, {
    bool isGroup = false,
  }) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ChatScreen(
          chatId: chatId,
          title: title,
          isGroup: isGroup,
        ),
      ),
    );
  }

  String _cleanError(Object e) {
    var text = e.toString();
    text = text.replaceFirst('Exception: ', '');

    if (text.contains('Failed to fetch')) {
      return 'Не удалось подключиться к серверу';
    }
    if (text.contains('TimeoutException')) {
      return 'Сервер не ответил вовремя';
    }
    if (text.contains('Chat request already pending')) {
      return 'Запрос уже отправлен';
    }
    if (text.contains('Chat already exists')) {
      return 'Чат уже существует';
    }
    if (text.contains('User not found')) {
      return 'Пользователь не найден';
    }
    if (text.contains('Invalid token')) {
      return 'Сессия устарела. Войдите заново';
    }

    return text;
  }

  void _showError(String message) {
    if (!mounted) return;
    TopNotification.error(context, message: message);
  }

  @override
  void dispose() {
    _wsSubscription?.cancel();
    _ws.dispose();
    super.dispose();
  }

  Future<void> _openMobileSideMenu() async {
    final accent = _whatsAppGreen;

    await showGeneralDialog<void>(
      context: context,
      barrierDismissible: true,
      barrierLabel: 'Меню',
      barrierColor: Colors.black.withValues(alpha: 0.30),
      transitionDuration: const Duration(milliseconds: 220),
      pageBuilder: (dialogContext, animation, secondaryAnimation) {
        return Align(
          alignment: Alignment.centerRight,
          child: Material(
            color: Colors.transparent,
            child: _MobileSideMenu(
              name: _myName.isNotEmpty ? _myName : 'UMe user',
              accent: accent,
              notificationsEnabled: _notificationsEnabled,
              onFindUser: () {
                Navigator.of(dialogContext).pop();
                _openSearchUsers();
              },
              onCreateGroup: () {
                Navigator.of(dialogContext).pop();
                _openCreateGroup();
              },
              onSettings: () {
                Navigator.of(dialogContext).pop();
                _openSettings();
              },
              onRefresh: () {
                Navigator.of(dialogContext).pop();
                _refresh();
              },
              onEnablePush: () {
                Navigator.of(dialogContext).pop();
                _enablePushNotifications();
              },
              onLogout: () {
                Navigator.of(dialogContext).pop();
                _logout();
              },
            ),
          ),
        );
      },
      transitionBuilder: (context, animation, secondaryAnimation, child) {
        final curved = CurvedAnimation(
          parent: animation,
          curve: Curves.easeOutCubic,
        );

        return SlideTransition(
          position: Tween<Offset>(
            begin: const Offset(1, 0),
            end: Offset.zero,
          ).animate(curved),
          child: FadeTransition(opacity: curved, child: child),
        );
      },
    );
  }

  String _formatChatTime(String? value) {
    if (value == null || value.trim().isEmpty) return '';

    final parsed = DateTime.tryParse(value);
    if (parsed == null) return '';

    final local = parsed.toLocal();
    final nowDate = DateTime.now();
    final today = DateTime(nowDate.year, nowDate.month, nowDate.day);
    final messageDay = DateTime(local.year, local.month, local.day);
    final difference = today.difference(messageDay).inDays;

    if (difference == 0) {
      final hour = local.hour.toString().padLeft(2, '0');
      final minute = local.minute.toString().padLeft(2, '0');
      return '$hour:$minute';
    }

    if (difference == 1) return 'Вчера';

    return '${local.day.toString().padLeft(2, '0')}.${local.month.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<Color>(
      valueListenable: accentColorNotifier,
      builder: (context, accent, _) {
        final incomingCount = _incomingRequests.length;
        final green = accent;
        final list = _visibleChats();
        final isDark = Theme.of(context).brightness == Brightness.dark;
        final pageColor = isDark ? const Color(0xFF0B141A) : const Color(0xFFF7F7F7);

        return Scaffold(
          backgroundColor: pageColor,
          body: Column(
            children: [
              _WhatsTopBar(
                green: green,
                name: _myName,
                chatsCount: _chats.length,
                incomingCount: incomingCount,
                selectedTab: _selectedTab,
                onMenu: _openMobileSideMenu,
                onChats: () => setState(() => _selectedTab = _ChatsTab.chats),
                onRequests: () => setState(() => _selectedTab = _ChatsTab.requests),
                onGroups: () => setState(() => _selectedTab = _ChatsTab.groups),
              ),
              Expanded(
                child: RefreshIndicator(
                  color: green,
                  onRefresh: _refresh,
                  child: _loading
                      ? ListView(
                          padding: EdgeInsets.zero,
                          children: const [
                            SizedBox(height: 240),
                            Center(child: CircularProgressIndicator()),
                          ],
                        )
                      : _selectedTab == _ChatsTab.requests
                          ? _RequestsTabBody(
                              green: green,
                              incomingRequests: _incomingRequests,
                              outgoingRequests: _outgoingRequests,
                              onAccept: (id) => _acceptRequest(id),
                              onDecline: (id) => _declineRequest(id),
                              onCancel: (id) => _cancelRequest(id),
                            )
                          : ListView(
                              padding: const EdgeInsets.fromLTRB(0, 0, 0, 24),
                              children: [
                                if (list.isEmpty)
                                  _WhatsEmptyChats(
                                    green: green,
                                    onFind: _openSearchUsers,
                                    message: _selectedTab == _ChatsTab.groups
                                        ? 'Групповых чатов пока нет'
                                        : 'Пока нет чатов',
                                  )
                                else
                                  ...list.map((item) {
                                    final chat = Map<String, dynamic>.from(item as Map);
                                    final chatId = chat['id']?.toString() ?? '';
                                    final title = chat['title']?.toString() ?? 'Чат';
                                    final avatarUrl = chat['avatar_url']?.toString();
                                    final isGroup = chat['is_group'] == true;
                                    final time = _formatChatTime(
                                      chat['last_message_created_at']?.toString(),
                                    );
                                    final subtitle = _chatSubtitle(chat);

                                    return _WhatsChatTile(
                                      green: green,
                                      title: title,
                                      subtitle: subtitle,
                                      time: time,
                                      avatarUrl: avatarUrl,
                                      isGroup: isGroup,
                                      onTap: () {
                                        if (chatId.isEmpty) return;
                                        _openChat(chatId, title, isGroup: isGroup);
                                      },
                                      onLongPress: () => _confirmDeleteChat(
                                        chatId,
                                        title,
                                        isGroup: isGroup,
                                      ),
                                    );
                                  }),
                              ],
                            ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  List<dynamic> _visibleChats() {
    if (_selectedTab == _ChatsTab.groups) {
      return _chats.where((item) {
        final chat = Map<String, dynamic>.from(item as Map);
        return chat['is_group'] == true;
      }).toList();
    }

    return _chats;
  }

  String _chatSubtitle(Map<String, dynamic> chat) {
    final lastMessage = chat['last_message_text']?.toString().trim();
    final lastType = chat['last_message_type']?.toString();
    final lastSender = chat['last_message_sender_name']?.toString().trim().isNotEmpty == true
        ? chat['last_message_sender_name'].toString().trim()
        : chat['last_sender_name']?.toString().trim().isNotEmpty == true
            ? chat['last_sender_name'].toString().trim()
            : chat['sender_name']?.toString().trim();

    final base = lastMessage != null && lastMessage.isNotEmpty
        ? lastMessage
        : _fallbackLastMessage(lastType);

    if (chat['is_group'] == true && lastSender != null && lastSender.isNotEmpty) {
      return '$lastSender: $base';
    }

    return base;
  }

  String _fallbackLastMessage(String? type) {
    switch (type) {
      case 'file':
        return 'Вложение';
      case 'text':
        return 'Сообщение';
      default:
        return 'Нет сообщений';
    }
  }
}

class _WhatsTopBar extends StatelessWidget {
  final Color green;
  final String name;
  final int chatsCount;
  final int incomingCount;
  final _ChatsTab selectedTab;
  final VoidCallback onMenu;
  final VoidCallback onChats;
  final VoidCallback onRequests;
  final VoidCallback onGroups;

  const _WhatsTopBar({
    required this.green,
    required this.name,
    required this.chatsCount,
    required this.incomingCount,
    required this.selectedTab,
    required this.onMenu,
    required this.onChats,
    required this.onRequests,
    required this.onGroups,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [green, const Color(0xFF128C7E)],
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.22),
            blurRadius: 16,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: SafeArea(
        bottom: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 8, 8, 6),
              child: Row(
                children: [
                  IconButton(
                    tooltip: 'Меню',
                    onPressed: onMenu,
                    icon: const Icon(Icons.menu_rounded),
                    color: Colors.white,
                  ),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'UMe',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 25,
                            height: 1,
                            fontWeight: FontWeight.w900,
                          ),
                        ),
                        if (name.isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(top: 3),
                            child: Text(
                              name,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: Colors.white.withValues(alpha: 0.82),
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(
              height: 52,
              child: Row(
                children: [
                  Expanded(
                    child: _WhatsTab(
                      title: 'ЧАТЫ',
                      active: selectedTab == _ChatsTab.chats,
                      badge: chatsCount,
                      onTap: onChats,
                    ),
                  ),
                  Expanded(
                    child: _WhatsTab(
                      title: 'ЗАПРОСЫ',
                      active: selectedTab == _ChatsTab.requests,
                      badge: incomingCount,
                      onTap: onRequests,
                    ),
                  ),
                  Expanded(
                    child: _WhatsTab(
                      title: 'ГРУППЫ',
                      active: selectedTab == _ChatsTab.groups,
                      badge: 0,
                      onTap: onGroups,
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

class _WhatsTab extends StatelessWidget {
  final String title;
  final bool active;
  final int badge;
  final VoidCallback onTap;

  const _WhatsTab({
    required this.title,
    required this.active,
    required this.badge,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Stack(
        alignment: Alignment.bottomCenter,
        children: [
          Center(
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: Colors.white.withValues(alpha: active ? 1.0 : 0.70),
                    fontWeight: FontWeight.w900,
                    letterSpacing: 0.2,
                  ),
                ),
                if (badge > 0) ...[
                  const SizedBox(width: 6),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                    decoration: BoxDecoration(
                      color: active ? Colors.white : Colors.white.withValues(alpha: 0.22),
                      borderRadius: BorderRadius.circular(999),
                    ),
                    child: Text(
                      badge > 99 ? '99+' : badge.toString(),
                      style: TextStyle(
                        color: active ? const Color(0xFF075E54) : Colors.white,
                        fontSize: 11,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          if (active)
            Container(
              height: 4,
              margin: const EdgeInsets.symmetric(horizontal: 10),
              decoration: const BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.vertical(top: Radius.circular(4)),
              ),
            ),
        ],
      ),
    );
  }
}

class _RequestsTabBody extends StatelessWidget {
  final Color green;
  final List<dynamic> incomingRequests;
  final List<dynamic> outgoingRequests;
  final Future<void> Function(String requestId) onAccept;
  final Future<void> Function(String requestId) onDecline;
  final Future<void> Function(String requestId) onCancel;

  const _RequestsTabBody({
    required this.green,
    required this.incomingRequests,
    required this.outgoingRequests,
    required this.onAccept,
    required this.onDecline,
    required this.onCancel,
  });

  @override
  Widget build(BuildContext context) {
    final hasAny = incomingRequests.isNotEmpty || outgoingRequests.isNotEmpty;

    if (!hasAny) {
      final isDark = Theme.of(context).brightness == Brightness.dark;
      final emptyTextColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF6F7479);

      return ListView(
        children: [
          const SizedBox(height: 160),
          Center(
            child: Text(
              'Нет активных запросов',
              style: TextStyle(
                color: emptyTextColor,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      );
    }

    return ListView(
      padding: EdgeInsets.zero,
      children: [
        if (incomingRequests.isNotEmpty) ...[
          _OldWhatsSectionTitle(title: 'Входящие'),
          ...incomingRequests.map((item) {
            final request = Map<String, dynamic>.from(item as Map);
            final requestId = request['id']?.toString() ?? '';
            final name = request['requester_name']?.toString() ?? 'Пользователь';
            final username = request['requester_username']?.toString() ?? '';
            final avatarUrl = request['requester_avatar_url']?.toString();

            return _RequestListTile(
              green: green,
              name: name,
              username: username,
              avatarUrl: avatarUrl,
              onAccept: requestId.isEmpty ? null : () => onAccept(requestId),
              onDecline: requestId.isEmpty ? null : () => onDecline(requestId),
            );
          }),
        ],
        if (outgoingRequests.isNotEmpty) ...[
          _OldWhatsSectionTitle(title: 'Исходящие'),
          ...outgoingRequests.map((item) {
            final request = Map<String, dynamic>.from(item as Map);
            final requestId = request['id']?.toString() ?? '';
            final name = request['receiver_name']?.toString() ?? 'Пользователь';
            final username = request['receiver_username']?.toString() ?? '';
            final avatarUrl = request['receiver_avatar_url']?.toString();

            return _RequestListTile(
              green: green,
              name: name,
              username: username.isEmpty ? 'ожидает ответа' : '@$username · ожидает ответа',
              avatarUrl: avatarUrl,
              onCancel: requestId.isEmpty ? null : () => onCancel(requestId),
            );
          }),
        ],
      ],
    );
  }
}

class _OldWhatsSectionTitle extends StatelessWidget {
  final String title;

  const _OldWhatsSectionTitle({required this.title});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      color: theme.brightness == Brightness.dark
          ? const Color(0xFF111B21)
          : const Color(0xFFEFEFEF),
      padding: const EdgeInsets.fromLTRB(16, 10, 16, 8),
      child: Text(
        title.toUpperCase(),
        style: TextStyle(
          color: theme.colorScheme.onSurface.withValues(alpha: 0.62),
          fontSize: 12,
          fontWeight: FontWeight.w900,
          letterSpacing: 0.7,
        ),
      ),
    );
  }
}

class _RequestListTile extends StatelessWidget {
  final Color green;
  final String name;
  final String username;
  final String? avatarUrl;
  final VoidCallback? onAccept;
  final VoidCallback? onDecline;
  final VoidCallback? onCancel;

  const _RequestListTile({
    required this.green,
    required this.name,
    required this.username,
    required this.avatarUrl,
    this.onAccept,
    this.onDecline,
    this.onCancel,
  });

  @override
  Widget build(BuildContext context) {
    final normalizedAvatar = avatarUrl == null || avatarUrl!.trim().isEmpty ? null : avatarUrl;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final tileColor = isDark ? const Color(0xFF111B21) : Colors.white;
    final titleColor = isDark ? const Color(0xFFE9EDEF) : const Color(0xFF111111);
    final subtitleColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF6F7479);
    final dividerColor = isDark ? const Color(0xFF222D34) : const Color(0xFFEAEAEA);

    return Material(
      color: tileColor,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 9, 12, 0),
        child: Row(
          children: [
            CircleAvatar(
              radius: 27,
              backgroundColor: green.withValues(alpha: 0.14),
              backgroundImage: normalizedAvatar == null
                  ? null
                  : NetworkImage(ApiClient.absoluteUrl(normalizedAvatar)),
              child: normalizedAvatar == null
                  ? Text(
                      name.isNotEmpty ? name.characters.first.toUpperCase() : '?',
                      style: TextStyle(
                        color: green,
                        fontWeight: FontWeight.w900,
                      ),
                    )
                  : null,
            ),
            const SizedBox(width: 13),
            Expanded(
              child: Container(
                padding: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(
                  border: Border(bottom: BorderSide(color: dividerColor)),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            name,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              color: titleColor,
                              fontSize: 16.2,
                              fontWeight: FontWeight.w900,
                            ),
                          ),
                          const SizedBox(height: 5),
                          Text(
                            username,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              color: subtitleColor,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (onDecline != null)
                      IconButton(
                        onPressed: onDecline,
                        icon: const Icon(Icons.close_rounded),
                      ),
                    if (onAccept != null)
                      IconButton(
                        onPressed: onAccept,
                        color: green,
                        icon: const Icon(Icons.check_rounded),
                      ),
                    if (onCancel != null)
                      TextButton(
                        onPressed: onCancel,
                        child: const Text('Отменить'),
                      ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _WhatsChatTile extends StatelessWidget {
  final Color green;
  final String title;
  final String subtitle;
  final String time;
  final String? avatarUrl;
  final bool isGroup;
  final VoidCallback onTap;
  final VoidCallback onLongPress;

  const _WhatsChatTile({
    required this.green,
    required this.title,
    required this.subtitle,
    required this.time,
    required this.avatarUrl,
    required this.isGroup,
    required this.onTap,
    required this.onLongPress,
  });

  @override
  Widget build(BuildContext context) {
    final normalizedAvatar = avatarUrl == null || avatarUrl!.trim().isEmpty ? null : avatarUrl;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final tileColor = isDark ? const Color(0xFF111B21) : Colors.white;
    final titleColor = isDark ? const Color(0xFFE9EDEF) : const Color(0xFF111111);
    final subtitleColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF6F7479);
    final dividerColor = isDark ? const Color(0xFF222D34) : const Color(0xFFEAEAEA);
    final mutedIconColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF8A8F94);

    return Material(
      color: tileColor,
      child: InkWell(
        onTap: onTap,
        onLongPress: onLongPress,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 9, 12, 0),
          child: Row(
            children: [
              CircleAvatar(
                radius: 27,
                backgroundColor: green.withValues(alpha: 0.14),
                backgroundImage: normalizedAvatar == null
                    ? null
                    : NetworkImage(ApiClient.absoluteUrl(normalizedAvatar)),
                child: normalizedAvatar == null
                    ? isGroup
                        ? Icon(Icons.groups_rounded, color: green)
                        : Text(
                            title.isNotEmpty ? title.characters.first.toUpperCase() : '?',
                            style: TextStyle(
                              color: green,
                              fontSize: 18,
                              fontWeight: FontWeight.w900,
                            ),
                          )
                    : null,
              ),
              const SizedBox(width: 13),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.only(bottom: 12),
                  decoration: BoxDecoration(
                    border: Border(bottom: BorderSide(color: dividerColor)),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              title,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: titleColor,
                                fontSize: 16.2,
                                fontWeight: FontWeight.w900,
                              ),
                            ),
                            const SizedBox(height: 5),
                            Row(
                              children: [
                                Icon(
                                  isGroup ? Icons.groups_2_rounded : Icons.done_all_rounded,
                                  color: mutedIconColor,
                                  size: 17,
                                ),
                                const SizedBox(width: 4),
                                Expanded(
                                  child: Text(
                                    subtitle,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: TextStyle(
                                      color: subtitleColor,
                                      fontSize: 14,
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      if (time.isNotEmpty)
                        Text(
                          time,
                          style: TextStyle(
                            color: green,
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                          ),
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
  }
}

class _WhatsEmptyChats extends StatelessWidget {
  final Color green;
  final VoidCallback onFind;
  final String message;

  const _WhatsEmptyChats({
    required this.green,
    required this.onFind,
    required this.message,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final titleColor = isDark ? const Color(0xFFE9EDEF) : const Color(0xFF111111);
    final subtitleColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF6F7479);

    return SizedBox(
      height: 430,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircleAvatar(
                radius: 38,
                backgroundColor: green,
                foregroundColor: Colors.white,
                child: const Icon(Icons.forum_rounded, size: 38),
              ),
              const SizedBox(height: 18),
              Text(
                message,
                style: TextStyle(
                  color: titleColor,
                  fontSize: 20,
                  fontWeight: FontWeight.w900,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                'Откройте меню и добавьте контакт',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: subtitleColor,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 18),
              FilledButton.icon(
                onPressed: onFind,
                style: FilledButton.styleFrom(
                  backgroundColor: green,
                  foregroundColor: Colors.white,
                ),
                icon: const Icon(Icons.person_search_rounded),
                label: const Text('Добавить контакт'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _MobileSideMenu extends StatelessWidget {
  final String name;
  final Color accent;
  final bool notificationsEnabled;
  final VoidCallback onFindUser;
  final VoidCallback onCreateGroup;
  final VoidCallback onSettings;
  final VoidCallback onRefresh;
  final VoidCallback onEnablePush;
  final VoidCallback onLogout;

  const _MobileSideMenu({
    required this.name,
    required this.accent,
    required this.notificationsEnabled,
    required this.onFindUser,
    required this.onCreateGroup,
    required this.onSettings,
    required this.onRefresh,
    required this.onEnablePush,
    required this.onLogout,
  });

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    final panelWidth = width < 430 ? width * 0.82 : 330.0;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final panelColor = isDark ? const Color(0xFF111B21) : const Color(0xFFF8F8F8);
    final footerColor = isDark ? const Color(0xFF8696A0) : Colors.black.withValues(alpha: 0.42);

    return Container(
      width: panelWidth,
      height: double.infinity,
      decoration: BoxDecoration(
        color: panelColor,
        boxShadow: const [
          BoxShadow(
            color: Color(0x33000000),
            blurRadius: 22,
            offset: Offset(-8, 0),
          ),
        ],
      ),
      child: SafeArea(
        left: false,
        child: Column(
          children: [
            _MobileSideProfileHeader(name: name, accent: accent),
            Expanded(
              child: ListView(
                padding: EdgeInsets.zero,
                children: [
                  _MobileSideMenuItem(
                    icon: Icons.person_add_alt_1_rounded,
                    title: 'Добавить контакт',
                    subtitle: 'Найти пользователя',
                    onTap: onFindUser,
                    accent: accent,
                  ),
                  _MobileSideMenuItem(
                    icon: Icons.group_add_rounded,
                    title: 'Создать группу',
                    subtitle: 'Новый групповой чат',
                    onTap: onCreateGroup,
                    accent: accent,
                  ),
                  if (!notificationsEnabled)
                    _MobileSideMenuItem(
                      icon: Icons.notifications_active_rounded,
                      title: 'Включить Push',
                      subtitle: 'Уведомления о сообщениях',
                      onTap: onEnablePush,
                      accent: accent,
                    ),
                  const _MobileSideDivider(),
                  _MobileSideMenuItem(
                    icon: Icons.settings_rounded,
                    title: 'Настройки',
                    subtitle: 'Профиль, внешний вид, уведомления',
                    onTap: onSettings,
                    accent: accent,
                  ),
                  _MobileSideMenuItem(
                    icon: Icons.refresh_rounded,
                    title: 'Обновить',
                    subtitle: 'Перезагрузить чаты',
                    onTap: onRefresh,
                    accent: accent,
                  ),
                  const _MobileSideDivider(),
                  _MobileSideMenuItem(
                    icon: Icons.logout_rounded,
                    title: 'Выйти из аккаунта',
                    subtitle: 'Завершить текущую сессию',
                    onTap: onLogout,
                    accent: const Color(0xFFD32F2F),
                    danger: true,
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(18, 10, 18, 18),
              child: Row(
                children: [
                  Icon(
                    Icons.lock_outline_rounded,
                    color: footerColor,
                    size: 18,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'UMe private messenger',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: footerColor,
                        fontWeight: FontWeight.w700,
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

class _MobileSideProfileHeader extends StatelessWidget {
  final String name;
  final Color accent;

  const _MobileSideProfileHeader({
    required this.name,
    required this.accent,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(20, 18, 20, 20),
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF075E54), Color(0xFF128C7E)],
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            radius: 33,
            backgroundColor: Colors.white,
            foregroundColor: accent,
            child: Text(
              name.isNotEmpty ? name.characters.first.toUpperCase() : 'U',
              style: const TextStyle(fontSize: 25, fontWeight: FontWeight.w900),
            ),
          ),
          const SizedBox(height: 13),
          Text(
            name,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 17,
              fontWeight: FontWeight.w900,
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileSideMenuItem extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  final Color accent;
  final bool danger;

  const _MobileSideMenuItem({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    required this.accent,
    this.danger = false,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final titleColor = danger
        ? const Color(0xFFD32F2F)
        : isDark
            ? const Color(0xFFE9EDEF)
            : const Color(0xFF111111);
    final subtitleColor = danger
        ? const Color(0xFFD32F2F).withValues(alpha: 0.72)
        : isDark
            ? const Color(0xFF8696A0)
            : const Color(0xFF6F7479);
    final arrowColor = isDark ? const Color(0xFF8696A0) : Colors.black.withValues(alpha: 0.25);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(18, 11, 16, 11),
          child: Row(
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  color: accent.withValues(alpha: danger ? 0.10 : 0.12),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Icon(icon, color: accent, size: 23),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: titleColor,
                        fontSize: 15.5,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: subtitleColor,
                        fontSize: 12.5,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right_rounded, color: arrowColor),
            ],
          ),
        ),
      ),
    );
  }
}

class _MobileSideDivider extends StatelessWidget {
  const _MobileSideDivider();

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Container(
      height: 1,
      margin: const EdgeInsets.symmetric(vertical: 8),
      color: isDark ? const Color(0xFF222D34) : const Color(0xFFE4E4E4),
    );
  }
}

class _UserSearchSheet extends StatefulWidget {
  final Color accent;
  final Future<void> Function() onRequestSent;
  final void Function(String message) onError;

  const _UserSearchSheet({
    required this.accent,
    required this.onRequestSent,
    required this.onError,
  });

  @override
  State<_UserSearchSheet> createState() => _UserSearchSheetState();
}

class _UserSearchSheetState extends State<_UserSearchSheet> {
  final _queryController = TextEditingController();

  bool _searching = false;
  bool _sending = false;

  List<dynamic> _results = [];

  Timer? _debounce;

  @override
  void dispose() {
    _debounce?.cancel();
    _queryController.dispose();
    super.dispose();
  }

  void _onQueryChanged(String value) {
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

      setState(() {
        _results = [];
      });

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
      widget.onError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _searching = false);
      }
    }
  }

  Future<void> _sendRequest(Map<String, dynamic> user) async {
    final userId = user['id']?.toString();

    if (userId == null || userId.isEmpty) return;

    setState(() => _sending = true);

    try {
      await ApiClient.post(
        '/chat-requests',
        {
          'receiver_user_id': userId,
        },
      );

      await widget.onRequestSent();

      if (!mounted) return;

      Navigator.of(context).pop();
    } catch (e) {
      widget.onError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _sending = false);
      }
    }
  }

  String _cleanError(Object e) {
    var text = e.toString();
    text = text.replaceFirst('Exception: ', '');

    if (text.contains('Chat request already pending')) {
      return 'Запрос уже отправлен';
    }

    if (text.contains('Chat already exists')) {
      return 'Чат уже существует';
    }

    if (text.contains('User not found')) {
      return 'Пользователь не найден';
    }

    if (text.contains('Failed to fetch')) {
      return 'Не удалось подключиться к серверу';
    }

    if (text.contains('TimeoutException')) {
      return 'Сервер не ответил вовремя';
    }

    return text;
  }

  @override
  Widget build(BuildContext context) {
    final bottom = MediaQuery.of(context).viewInsets.bottom;

    return Padding(
      padding: EdgeInsets.fromLTRB(16, 8, 16, bottom + 16),
      child: SafeArea(
        top: false,
        child: SizedBox(
          height: MediaQuery.of(context).size.height * 0.78,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Найти пользователя',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _queryController,
                autofocus: true,
                enabled: !_sending,
                onChanged: _onQueryChanged,
                decoration: InputDecoration(
                  labelText: 'Username, никнейм или имя',
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
              Expanded(
                child: _results.isEmpty
                    ? Center(
                        child: Text(
                          _queryController.text.trim().length < 2
                              ? 'Введите минимум 2 символа'
                              : 'Ничего не найдено',
                        ),
                      )
                    : ListView.builder(
                        itemCount: _results.length,
                        itemBuilder: (context, index) {
                          final user = Map<String, dynamic>.from(
                            _results[index] as Map,
                          );

                          final title =
                              user['display_name']?.toString().trim().isNotEmpty ==
                                      true
                                  ? user['display_name'].toString()
                                  : user['nickname']
                                              ?.toString()
                                              .trim()
                                              .isNotEmpty ==
                                          true
                                      ? user['nickname'].toString()
                                      : user['username']?.toString() ??
                                          'Пользователь';

                          final username = user['username']?.toString() ?? '';
                          final avatarUrl = user['avatar_url']?.toString();

                          return Card(
                            child: ListTile(
                              leading: CircleAvatar(
                                backgroundColor: widget.accent.withValues(alpha: 0.16),
                                backgroundImage:
                                    avatarUrl == null || avatarUrl.isEmpty
                                        ? null
                                        : NetworkImage(
                                            ApiClient.absoluteUrl(avatarUrl),
                                          ),
                                child: avatarUrl == null || avatarUrl.isEmpty
                                    ? Text(
                                        title.isNotEmpty
                                            ? title.characters.first
                                                .toUpperCase()
                                            : '?',
                                        style: TextStyle(
                                          color: widget.accent,
                                          fontWeight: FontWeight.w900,
                                        ),
                                      )
                                    : null,
                              ),
                              title: Text(title),
                              subtitle:
                                  username.isEmpty ? null : Text('@$username'),
                              trailing: FilledButton(
                                onPressed:
                                    _sending ? null : () => _sendRequest(user),
                                style: FilledButton.styleFrom(
                                  backgroundColor: widget.accent,
                                  foregroundColor: widget.accent.computeLuminance() > 0.55
                                      ? Colors.black
                                      : Colors.white,
                                ),
                                child: const Text('Запрос'),
                              ),
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

