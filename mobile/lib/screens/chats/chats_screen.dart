import 'dart:async';
import 'package:flutter/material.dart';

import '../../core/api_client.dart';
import '../../core/onesignal_service.dart';
import '../../core/websocket_service.dart';
import '../../widgets/top_notification.dart';
import '../messages/chat_screen.dart';
import 'create_group_screen.dart';
import '../settings/settings_screen.dart';

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
  String _accentColor = 'blue';


  List<dynamic> _chats = [];
  List<dynamic> _incomingRequests = [];
  List<dynamic> _outgoingRequests = [];

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
        _accentColor = me['accent_color']?.toString() ?? 'blue';
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
      setState(() {
        _refreshing = true;
      });
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
        setState(() {
          _refreshing = false;
        });
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

      setState(() {
        _notificationsEnabled = true;
      });

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


  Future<void> _openSettings() async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => const SettingsScreen(),
      ),
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
          accent: _accentColorValue(),
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

  Future<void> _openRequests() async {
    await _loadRequests(silent: true);

    if (!mounted) return;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (sheetContext) {
        return _ChatRequestsSheet(
          accent: _accentColorValue(),
          incomingRequests: _incomingRequests,
          outgoingRequests: _outgoingRequests,
          onAccept: _acceptRequest,
          onDecline: _declineRequest,
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

      Navigator.of(context).pop();

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

      Navigator.of(context).pop();

      TopNotification.info(
        context,
        message: 'Запрос отклонён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _openCreateGroup() async {
    final result = await Navigator.of(context).push<Map<String, dynamic>>(
      MaterialPageRoute(
        builder: (_) => const CreateGroupScreen(),
      ),
    );

    if (!mounted) return;

    await _loadChats(silent: true);

    if (result == null) return;

    final chatId = result['id']?.toString();
    final title = result['title']?.toString() ?? 'Группа';

    if (chatId != null && chatId.isNotEmpty) {
      _openChat(
        chatId,
        title,
        isGroup: true,
      );
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

  Color _accentColorValue() {
    final parsed = _parseAccentColor(_accentColor);

    if (parsed != null) return parsed;

    switch (_accentColor) {
      case 'green':
        return Colors.green;
      case 'purple':
        return Colors.purple;
      case 'orange':
        return Colors.orange;
      case 'pink':
        return Colors.pink;
      case 'blue':
      default:
        return Colors.blue;
    }
  }

  Color? _parseAccentColor(String value) {
    final text = value.trim();

    if (!text.startsWith('#')) return null;

    final hex = text.substring(1);

    if (hex.length != 6 && hex.length != 8) return null;

    final parsed = int.tryParse(hex, radix: 16);

    if (parsed == null) return null;

    if (hex.length == 6) {
      return Color(0xFF000000 | parsed);
    }

    return Color(parsed);
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

    TopNotification.error(
      context,
      message: message,
    );
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
      barrierColor: Colors.black.withValues(alpha: 0.45),
      transitionDuration: const Duration(milliseconds: 230),
      pageBuilder: (dialogContext, animation, secondaryAnimation) {
        return Align(
          alignment: Alignment.centerLeft,
          child: Material(
            color: Colors.transparent,
            child: _MobileSideMenu(
              name: _myName.isNotEmpty ? _myName : 'UMe user',
              accent: accent,
              incomingCount: _incomingRequests.length,
              outgoingCount: _outgoingRequests.length,
              notificationsEnabled: _notificationsEnabled,
              onFindUser: () {
                Navigator.of(dialogContext).pop();
                _openSearchUsers();
              },
              onCreateGroup: () {
                Navigator.of(dialogContext).pop();
                _openCreateGroup();
              },
              onRequests: () {
                Navigator.of(dialogContext).pop();
                _openRequests();
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
            begin: const Offset(-1, 0),
            end: Offset.zero,
          ).animate(curved),
          child: FadeTransition(
            opacity: curved,
            child: child,
          ),
        );
      },
    );
  }

  Color get _whatsAppGreen => const Color(0xFF075E54);

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
    final incomingCount = _incomingRequests.length;
    final outgoingCount = _outgoingRequests.length;
    final green = _whatsAppGreen;
    final fabGreen = const Color(0xFF25D366);

    return Scaffold(
      backgroundColor: const Color(0xFFF7F7F7),
      floatingActionButton: FloatingActionButton(
        onPressed: _openSearchUsers,
        backgroundColor: fabGreen,
        foregroundColor: Colors.white,
        elevation: 7,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(18),
        ),
        child: const Icon(Icons.chat_rounded),
      ),
      body: Column(
        children: [
          _WhatsTopBar(
            green: green,
            name: _myName,
            chatsCount: _chats.length,
            incomingCount: incomingCount,
            onMenu: _openMobileSideMenu,
            onSearch: _openSearchUsers,
          ),
          Expanded(
            child: RefreshIndicator(
              color: fabGreen,
              onRefresh: _refresh,
              child: _loading
                  ? ListView(
                      padding: EdgeInsets.zero,
                      children: const [
                        SizedBox(height: 240),
                        Center(child: CircularProgressIndicator()),
                      ],
                    )
                  : ListView(
                      padding: const EdgeInsets.fromLTRB(0, 0, 0, 96),
                      children: [
                        if (incomingCount > 0 || outgoingCount > 0)
                          _WhatsRequestsBanner(
                            green: green,
                            incomingCount: incomingCount,
                            outgoingCount: outgoingCount,
                            onTap: _openRequests,
                          ),
                        if (_chats.isEmpty)
                          _WhatsEmptyChats(
                            green: green,
                            onFind: _openSearchUsers,
                          )
                        else
                          ..._chats.map((item) {
                            final chat = Map<String, dynamic>.from(item as Map);
                            final chatId = chat['id']?.toString() ?? '';
                            final title = chat['title']?.toString() ?? 'Чат';
                            final avatarUrl = chat['avatar_url']?.toString();
                            final isGroup = chat['is_group'] == true;
                            final memberCount = chat['member_count'] is int
                                ? chat['member_count'] as int
                                : int.tryParse(chat['member_count']?.toString() ?? '') ?? 0;
                            final lastMessage = chat['last_message_text']?.toString().trim();
                            final lastType = chat['last_message_type']?.toString();
                            final time = _formatChatTime(
                              chat['last_message_created_at']?.toString(),
                            );
                            final baseSubtitle = lastMessage != null && lastMessage.isNotEmpty
                                ? lastMessage
                                : _fallbackLastMessage(lastType);

                            return _WhatsChatTile(
                              green: green,
                              title: title,
                              subtitle: isGroup
                                  ? 'Группа · $memberCount участн. · $baseSubtitle'
                                  : baseSubtitle,
                              time: time,
                              avatarUrl: avatarUrl,
                              isGroup: isGroup,
                              onTap: () {
                                if (chatId.isEmpty) return;

                                _openChat(
                                  chatId,
                                  title,
                                  isGroup: isGroup,
                                );
                              },
                            );
                          }),
                      ],
                    ),
            ),
          ),
        ],
      ),
    );
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
  final VoidCallback onMenu;
  final VoidCallback onSearch;

  const _WhatsTopBar({
    required this.green,
    required this.name,
    required this.chatsCount,
    required this.incomingCount,
    required this.onMenu,
    required this.onSearch,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            green,
            const Color(0xFF128C7E),
          ],
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
                  IconButton(
                    tooltip: 'Поиск',
                    onPressed: onSearch,
                    icon: const Icon(Icons.search_rounded),
                    color: Colors.white,
                  ),
                ],
              ),
            ),
            SizedBox(
              height: 52,
              child: Row(
                children: [
                  const SizedBox(width: 12),
                  SizedBox(
                    width: 44,
                    child: Icon(
                      Icons.camera_alt_rounded,
                      color: Colors.white.withValues(alpha: 0.82),
                      size: 22,
                    ),
                  ),
                  Expanded(
                    child: _WhatsTab(
                      title: 'ЧАТЫ',
                      active: true,
                      badge: chatsCount,
                    ),
                  ),
                  Expanded(
                    child: _WhatsTab(
                      title: 'ЗАПРОСЫ',
                      active: false,
                      badge: incomingCount,
                    ),
                  ),
                  const Expanded(
                    child: _WhatsTab(
                      title: 'ГРУППЫ',
                      active: false,
                      badge: 0,
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

  const _WhatsTab({
    required this.title,
    required this.active,
    required this.badge,
  });

  @override
  Widget build(BuildContext context) {
    return Stack(
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
              borderRadius: BorderRadius.vertical(
                top: Radius.circular(4),
              ),
            ),
          ),
      ],
    );
  }
}

class _WhatsRequestsBanner extends StatelessWidget {
  final Color green;
  final int incomingCount;
  final int outgoingCount;
  final VoidCallback onTap;

  const _WhatsRequestsBanner({
    required this.green,
    required this.incomingCount,
    required this.outgoingCount,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final parts = <String>[];

    if (incomingCount > 0) parts.add('входящие: $incomingCount');
    if (outgoingCount > 0) parts.add('исходящие: $outgoingCount');

    return Material(
      color: const Color(0xFFE8F5E9),
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              CircleAvatar(
                radius: 22,
                backgroundColor: green,
                foregroundColor: Colors.white,
                child: const Icon(Icons.mark_email_unread_rounded, size: 21),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Запросы на чат',
                      style: TextStyle(
                        color: Color(0xFF202124),
                        fontWeight: FontWeight.w900,
                        fontSize: 15.5,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      parts.join(' · '),
                      style: const TextStyle(
                        color: Color(0xFF5F6368),
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right_rounded, color: green),
            ],
          ),
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

  const _WhatsChatTile({
    required this.green,
    required this.title,
    required this.subtitle,
    required this.time,
    required this.avatarUrl,
    required this.isGroup,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final normalizedAvatar =
        avatarUrl == null || avatarUrl!.trim().isEmpty ? null : avatarUrl;

    return Material(
      color: Colors.white,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 9, 12, 0),
          child: Row(
            children: [
              CircleAvatar(
                radius: 27,
                backgroundColor: const Color(0xFFE2F0EC),
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
                  decoration: const BoxDecoration(
                    border: Border(
                      bottom: BorderSide(
                        color: Color(0xFFEAEAEA),
                      ),
                    ),
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
                              style: const TextStyle(
                                color: Color(0xFF111111),
                                fontSize: 16.2,
                                fontWeight: FontWeight.w900,
                              ),
                            ),
                            const SizedBox(height: 5),
                            Row(
                              children: [
                                Icon(
                                  isGroup ? Icons.groups_2_rounded : Icons.done_all_rounded,
                                  color: const Color(0xFF8A8F94),
                                  size: 17,
                                ),
                                const SizedBox(width: 4),
                                Expanded(
                                  child: Text(
                                    subtitle,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: const TextStyle(
                                      color: Color(0xFF6F7479),
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
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                          if (time.isNotEmpty)
                            Text(
                              time,
                              style: TextStyle(
                                color: green,
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                              ),
                            )
                          else
                            const SizedBox(height: 14),
                          const SizedBox(height: 9),
                          if (isGroup)
                            Container(
                              width: 20,
                              height: 20,
                              alignment: Alignment.center,
                              decoration: BoxDecoration(
                                color: const Color(0xFF25D366),
                                borderRadius: BorderRadius.circular(999),
                              ),
                              child: const Text(
                                'G',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 10,
                                  fontWeight: FontWeight.w900,
                                ),
                              ),
                            ),
                        ],
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

  const _WhatsEmptyChats({
    required this.green,
    required this.onFind,
  });

  @override
  Widget build(BuildContext context) {
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
              const Text(
                'Пока нет чатов',
                style: TextStyle(
                  color: Color(0xFF111111),
                  fontSize: 20,
                  fontWeight: FontWeight.w900,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Найдите пользователя и отправьте запрос на чат',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Color(0xFF6F7479),
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
                label: const Text('Найти пользователя'),
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
  final int incomingCount;
  final int outgoingCount;
  final bool notificationsEnabled;
  final VoidCallback onFindUser;
  final VoidCallback onCreateGroup;
  final VoidCallback onRequests;
  final VoidCallback onSettings;
  final VoidCallback onRefresh;
  final VoidCallback onEnablePush;

  const _MobileSideMenu({
    required this.name,
    required this.accent,
    required this.incomingCount,
    required this.outgoingCount,
    required this.notificationsEnabled,
    required this.onFindUser,
    required this.onCreateGroup,
    required this.onRequests,
    required this.onSettings,
    required this.onRefresh,
    required this.onEnablePush,
  });

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    final panelWidth = width < 420 ? width * 0.86 : 338.0;

    return Container(
      width: panelWidth,
      height: double.infinity,
      color: const Color(0xFF17212B),
      child: SafeArea(
        right: false,
        child: Column(
          children: [
            _MobileSideProfileHeader(
              name: name,
              accent: accent,
            ),
            Expanded(
              child: ListView(
                padding: EdgeInsets.zero,
                children: [
                  _MobileSideAccountTile(
                    name: name,
                    accent: accent,
                    selected: true,
                  ),
                  _MobileSideMenuItem(
                    icon: Icons.add_circle_rounded,
                    title: 'Добавить контакт',
                    onTap: onFindUser,
                    iconColor: const Color(0xFF62A8EA),
                  ),
                  const _MobileSideDivider(),
                  _MobileSideMenuItem(
                    icon: Icons.person_outline_rounded,
                    title: 'Мой профиль',
                    onTap: onSettings,
                  ),
                  _MobileSideMenuItem(
                    icon: Icons.group_add_rounded,
                    title: 'Создать группу',
                    onTap: onCreateGroup,
                  ),
                  _MobileSideMenuItem(
                    icon: Icons.mark_email_unread_rounded,
                    title: 'Запросы',
                    badge: incomingCount > 0 ? incomingCount.toString() : null,
                    onTap: onRequests,
                  ),
                  if (!notificationsEnabled)
                    _MobileSideMenuItem(
                      icon: Icons.notifications_active_rounded,
                      title: 'Включить Push',
                      onTap: onEnablePush,
                    ),
                  _MobileSideMenuItem(
                    icon: Icons.settings_rounded,
                    title: 'Настройки',
                    onTap: onSettings,
                  ),
                  _MobileSideMenuItem(
                    icon: Icons.refresh_rounded,
                    title: 'Обновить',
                    onTap: onRefresh,
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
                    color: Colors.white.withValues(alpha: 0.45),
                    size: 18,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'UMe private messenger',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: Colors.white.withValues(alpha: 0.45),
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
      padding: const EdgeInsets.fromLTRB(20, 18, 20, 18),
      decoration: const BoxDecoration(
        color: Color(0xFF17212B),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            radius: 33,
            backgroundColor: accent,
            foregroundColor: Colors.white,
            child: Text(
              name.isNotEmpty ? name.characters.first.toUpperCase() : 'U',
              style: const TextStyle(
                fontSize: 25,
                fontWeight: FontWeight.w900,
              ),
            ),
          ),
          const SizedBox(height: 12),
          Text(
            name,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 16,
              fontWeight: FontWeight.w900,
            ),
          ),
          const SizedBox(height: 4),
          const Text(
            'Сменить UMe-статус',
            style: TextStyle(
              color: Color(0xFF6AB3F3),
              fontSize: 14,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileSideAccountTile extends StatelessWidget {
  final String name;
  final Color accent;
  final bool selected;

  const _MobileSideAccountTile({
    required this.name,
    required this.accent,
    required this.selected,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      dense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 4),
      leading: CircleAvatar(
        radius: 19,
        backgroundColor: accent.withValues(alpha: 0.22),
        foregroundColor: Colors.white,
        child: Text(
          name.isNotEmpty ? name.characters.first.toUpperCase() : 'U',
          style: const TextStyle(fontWeight: FontWeight.w900),
        ),
      ),
      title: Text(
        name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(
          color: Colors.white,
          fontWeight: FontWeight.w900,
        ),
      ),
      trailing: selected
          ? Icon(
              Icons.check_rounded,
              color: accent,
            )
          : null,
    );
  }
}

class _MobileSideMenuItem extends StatelessWidget {
  final IconData icon;
  final String title;
  final VoidCallback onTap;
  final String? badge;
  final Color? iconColor;

  const _MobileSideMenuItem({
    required this.icon,
    required this.title,
    required this.onTap,
    this.badge,
    this.iconColor,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 12, 18, 12),
        child: Row(
          children: [
            Icon(
              icon,
              color: iconColor ?? Colors.white.withValues(alpha: 0.82),
              size: 24,
            ),
            const SizedBox(width: 22),
            Expanded(
              child: Text(
                title,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 15,
                  fontWeight: FontWeight.w800,
                ),
              ),
            ),
            if (badge != null)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: const Color(0xFF54A9EB),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  badge!,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w900,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _MobileSideDivider extends StatelessWidget {
  const _MobileSideDivider();

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 1,
      margin: const EdgeInsets.symmetric(vertical: 8),
      color: Colors.black.withValues(alpha: 0.18),
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

class _ChatRequestsSheet extends StatelessWidget {
  final Color accent;
  final List<dynamic> incomingRequests;
  final List<dynamic> outgoingRequests;
  final Future<void> Function(String requestId) onAccept;
  final Future<void> Function(String requestId) onDecline;

  const _ChatRequestsSheet({
    required this.accent,
    required this.incomingRequests,
    required this.outgoingRequests,
    required this.onAccept,
    required this.onDecline,
  });

  @override
  Widget build(BuildContext context) {
    final hasAny = incomingRequests.isNotEmpty || outgoingRequests.isNotEmpty;
    final bottom = MediaQuery.of(context).viewInsets.bottom;

    return Padding(
      padding: EdgeInsets.fromLTRB(16, 8, 16, bottom + 16),
      child: SafeArea(
        top: false,
        child: SizedBox(
          height: MediaQuery.of(context).size.height * 0.75,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Запросы на чат',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 12),
              if (!hasAny)
                const Expanded(
                  child: Center(
                    child: Text('Нет активных запросов'),
                  ),
                )
              else
                Expanded(
                  child: ListView(
                    children: [
                      if (incomingRequests.isNotEmpty) ...[
                        Text(
                          'Входящие',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        ...incomingRequests.map((item) {
                          final request = Map<String, dynamic>.from(
                            item as Map,
                          );

                          final requestId = request['id']?.toString() ?? '';
                          final name =
                              request['requester_name']?.toString() ??
                                  'Пользователь';
                          final username =
                              request['requester_username']?.toString() ?? '';
                          final avatarUrl =
                              request['requester_avatar_url']?.toString();

                          return Card(
                            child: ListTile(
                              leading: CircleAvatar(
                                backgroundColor: accent.withValues(alpha: 0.16),
                                backgroundImage:
                                    avatarUrl == null || avatarUrl.isEmpty
                                        ? null
                                        : NetworkImage(
                                            ApiClient.absoluteUrl(avatarUrl),
                                          ),
                                child: avatarUrl == null || avatarUrl.isEmpty
                                    ? Text(
                                        name.isNotEmpty
                                            ? name.characters.first
                                                .toUpperCase()
                                            : '?',
                                        style: TextStyle(
                                          color: accent,
                                          fontWeight: FontWeight.w900,
                                        ),
                                      )
                                    : null,
                              ),
                              title: Text(name),
                              subtitle:
                                  username.isEmpty ? null : Text('@$username'),
                              trailing: Wrap(
                                spacing: 8,
                                children: [
                                  IconButton.filledTonal(
                                    tooltip: 'Отклонить',
                                    onPressed: requestId.isEmpty
                                        ? null
                                        : () => onDecline(requestId),
                                    icon: const Icon(Icons.close),
                                  ),
                                  IconButton.filled(
                                    tooltip: 'Принять',
                                    onPressed: requestId.isEmpty
                                        ? null
                                        : () => onAccept(requestId),
                                    style: IconButton.styleFrom(
                                      backgroundColor: accent,
                                      foregroundColor: accent.computeLuminance() > 0.55
                                          ? Colors.black
                                          : Colors.white,
                                    ),
                                    icon: const Icon(Icons.check),
                                  ),
                                ],
                              ),
                            ),
                          );
                        }),
                        const SizedBox(height: 16),
                      ],
                      if (outgoingRequests.isNotEmpty) ...[
                        Text(
                          'Исходящие',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        ...outgoingRequests.map((item) {
                          final request = Map<String, dynamic>.from(
                            item as Map,
                          );

                          final name = request['receiver_name']?.toString() ??
                              'Пользователь';
                          final username =
                              request['receiver_username']?.toString() ?? '';
                          final avatarUrl =
                              request['receiver_avatar_url']?.toString();

                          return Card(
                            child: ListTile(
                              leading: CircleAvatar(
                                backgroundColor: accent.withValues(alpha: 0.16),
                                backgroundImage:
                                    avatarUrl == null || avatarUrl.isEmpty
                                        ? null
                                        : NetworkImage(
                                            ApiClient.absoluteUrl(avatarUrl),
                                          ),
                                child: avatarUrl == null || avatarUrl.isEmpty
                                    ? Text(
                                        name.isNotEmpty
                                            ? name.characters.first
                                                .toUpperCase()
                                            : '?',
                                        style: TextStyle(
                                          color: accent,
                                          fontWeight: FontWeight.w900,
                                        ),
                                      )
                                    : null,
                              ),
                              title: Text(name),
                              subtitle: Text(
                                username.isEmpty
                                    ? 'Ожидает ответа'
                                    : '@$username · ожидает ответа',
                              ),
                              trailing: Icon(Icons.schedule, color: accent),
                            ),
                          );
                        }),
                      ],
                    ],
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
