import 'dart:async';
import 'dart:ui';

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
  String _chatWallpaper = 'default';

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
        _chatWallpaper = me['chat_wallpaper']?.toString() ?? 'default';
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
    await _loadMe();
    await _loadAll(silent: false);

    if (!mounted) return;

    TopNotification.success(
      context,
      message: 'Чаты обновлены',
    );
  }

  Future<void> _openMobileSideMenu() async {
    final accent = _accentColorValue();

    await showGeneralDialog<void>(
      context: context,
      barrierDismissible: true,
      barrierLabel: 'Меню',
      barrierColor: Colors.black.withValues(alpha: 0.42),
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
              refreshing: _refreshing,
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

  BoxDecoration _backgroundDecoration(BuildContext context) {
    final accent = _accentColorValue();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final isCustomWallpaper = _chatWallpaper.startsWith('/uploads/') ||
        _chatWallpaper.startsWith('http://') ||
        _chatWallpaper.startsWith('https://');

    if (isCustomWallpaper) {
      return BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        image: DecorationImage(
          image: NetworkImage(ApiClient.absoluteUrl(_chatWallpaper)),
          fit: BoxFit.cover,
          colorFilter: ColorFilter.mode(
            Colors.black.withValues(alpha: isDark ? 0.55 : 0.28),
            BlendMode.darken,
          ),
        ),
      );
    }

    return BoxDecoration(
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          accent.withValues(alpha: isDark ? 0.28 : 0.18),
          Theme.of(context).colorScheme.surface,
          accent.withValues(alpha: isDark ? 0.18 : 0.10),
        ],
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

  @override
  Widget build(BuildContext context) {
    final incomingCount = _incomingRequests.length;
    final outgoingCount = _outgoingRequests.length;
    final accent = _accentColorValue();
    final onAccent = accent.computeLuminance() > 0.55 ? Colors.black : Colors.white;

    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        leading: IconButton(
          tooltip: 'Меню',
          onPressed: _openMobileSideMenu,
          icon: const Icon(Icons.menu_rounded),
        ),
        titleSpacing: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'UMe',
              style: TextStyle(fontWeight: FontWeight.w900),
            ),
            if (_myName.isNotEmpty)
              Text(
                _myName,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ),
        elevation: 0,
        scrolledUnderElevation: 0,
        backgroundColor: Theme.of(context).colorScheme.surface.withValues(alpha: 0.68),
        foregroundColor: Theme.of(context).colorScheme.onSurface,
        actions: [
          IconButton(
            tooltip: 'Поиск',
            onPressed: _openSearchUsers,
            icon: const Icon(Icons.search_rounded),
          ),
          const SizedBox(width: 4),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _openSearchUsers,
        backgroundColor: accent,
        foregroundColor: onAccent,
        icon: const Icon(Icons.person_search),
        label: const Text('Найти'),
      ),
      body: DecoratedBox(
        decoration: _backgroundDecoration(context),
        child: SafeArea(
          child: RefreshIndicator(
            onRefresh: _refresh,
            child: _loading
                ? ListView(
                    children: const [
                      SizedBox(height: 220),
                      Center(child: CircularProgressIndicator()),
                    ],
                  )
                : ListView(
                    padding: const EdgeInsets.fromLTRB(12, 12, 12, 96),
                    children: [
                      _HeaderCard(
                        name: _myName,
                        accent: accent,
                        notificationsEnabled: _notificationsEnabled,
                      ),
                      const SizedBox(height: 12),
                      _QuickActionsGrid(
                        accent: accent,
                        notificationsEnabled: _notificationsEnabled,
                        incomingCount: incomingCount,
                        onSearch: _openSearchUsers,
                        onCreateGroup: _openCreateGroup,
                        onRequests: _openRequests,
                        onEnableNotifications: () => _enablePushNotifications(),
                      ),
                      const SizedBox(height: 12),
                      if (incomingCount > 0 || outgoingCount > 0)
                        _RequestsSummaryCard(
                          accent: accent,
                          incomingCount: incomingCount,
                          outgoingCount: outgoingCount,
                          onTap: _openRequests,
                        ),
                      if (_chats.isEmpty)
                        _EmptyChatsCard(accent: accent)
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
                          final lastMessage =
                              chat['last_message_text']?.toString().trim();
                          final lastType = chat['last_message_type']?.toString();
                          final baseSubtitle = lastMessage != null && lastMessage.isNotEmpty
                              ? lastMessage
                              : _fallbackLastMessage(lastType);

                          return _ChatTile(
                            accent: accent,
                            title: title,
                            subtitle: isGroup
                                ? 'Группа · $memberCount участн. · $baseSubtitle'
                                : baseSubtitle,
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

class _HeaderCard extends StatelessWidget {
  final String name;
  final Color accent;
  final bool notificationsEnabled;

  const _HeaderCard({
    required this.name,
    required this.accent,
    required this.notificationsEnabled,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surface.withValues(alpha: 0.76),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(24),
        side: BorderSide(
          color: accent.withValues(alpha: 0.22),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(
              backgroundColor: accent,
              foregroundColor: accent.computeLuminance() > 0.55 ? Colors.black : Colors.white,
              child: const Icon(Icons.forum_outlined),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'UMe Messenger',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.w900,
                        ),
                  ),
                  if (name.isNotEmpty)
                    Text(
                      'Вы вошли как $name',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 8,
                    runSpacing: 6,
                    children: [
                      _StatusPill(
                        icon: Icons.lock_outline,
                        text: 'личные чаты',
                        accent: accent,
                      ),
                      _StatusPill(
                        icon: notificationsEnabled
                            ? Icons.notifications_active_outlined
                            : Icons.notifications_none_outlined,
                        text: notificationsEnabled ? 'уведомления включены' : 'уведомления не включены',
                        accent: accent,
                      ),
                    ],
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


class _StatusPill extends StatelessWidget {
  final IconData icon;
  final String text;
  final Color accent;

  const _StatusPill({
    required this.icon,
    required this.text,
    required this.accent,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: accent.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: accent.withValues(alpha: 0.18)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 15, color: accent),
          const SizedBox(width: 5),
          Text(
            text,
            style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
          ),
        ],
      ),
    );
  }
}

class _QuickActionsGrid extends StatelessWidget {
  final Color accent;
  final bool notificationsEnabled;
  final int incomingCount;
  final VoidCallback onSearch;
  final VoidCallback onCreateGroup;
  final VoidCallback onRequests;
  final VoidCallback onEnableNotifications;

  const _QuickActionsGrid({
    required this.accent,
    required this.notificationsEnabled,
    required this.incomingCount,
    required this.onSearch,
    required this.onCreateGroup,
    required this.onRequests,
    required this.onEnableNotifications,
  });

  @override
  Widget build(BuildContext context) {
    final actions = <_QuickActionData>[
      _QuickActionData(
        icon: Icons.person_search,
        title: 'Найти',
        subtitle: 'новый чат',
        onTap: onSearch,
      ),
      _QuickActionData(
        icon: Icons.group_add_outlined,
        title: 'Группа',
        subtitle: 'создать',
        onTap: onCreateGroup,
      ),
      _QuickActionData(
        icon: Icons.mark_email_unread_outlined,
        title: 'Запросы',
        subtitle: incomingCount > 0 ? '$incomingCount вход.' : 'проверить',
        badge: incomingCount,
        onTap: onRequests,
      ),
      if (!notificationsEnabled)
        _QuickActionData(
          icon: Icons.notifications_active_outlined,
          title: 'Push',
          subtitle: 'включить',
          onTap: onEnableNotifications,
        ),
    ];

    return LayoutBuilder(
      builder: (context, constraints) {
        final columns = constraints.maxWidth > 520 ? 4 : 2;
        final spacing = 10.0;
        final itemWidth = (constraints.maxWidth - spacing * (columns - 1)) / columns;

        return Wrap(
          spacing: spacing,
          runSpacing: spacing,
          children: actions.map((action) {
            return SizedBox(
              width: itemWidth,
              child: _QuickActionCard(
                accent: accent,
                data: action,
              ),
            );
          }).toList(),
        );
      },
    );
  }
}

class _QuickActionData {
  final IconData icon;
  final String title;
  final String subtitle;
  final int badge;
  final VoidCallback onTap;

  const _QuickActionData({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.badge = 0,
  });
}

class _QuickActionCard extends StatelessWidget {
  final Color accent;
  final _QuickActionData data;

  const _QuickActionCard({
    required this.accent,
    required this.data,
  });

  @override
  Widget build(BuildContext context) {
    final onAccent = accent.computeLuminance() > 0.55 ? Colors.black : Colors.white;

    return Material(
      color: Theme.of(context).colorScheme.surface.withValues(alpha: 0.82),
      borderRadius: BorderRadius.circular(22),
      child: InkWell(
        borderRadius: BorderRadius.circular(22),
        onTap: data.onTap,
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(22),
            border: Border.all(color: accent.withValues(alpha: 0.16)),
          ),
          child: Row(
            children: [
              Stack(
                clipBehavior: Clip.none,
                children: [
                  CircleAvatar(
                    radius: 22,
                    backgroundColor: accent,
                    foregroundColor: onAccent,
                    child: Icon(data.icon, size: 22),
                  ),
                  if (data.badge > 0)
                    Positioned(
                      right: -4,
                      top: -5,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.error,
                          borderRadius: BorderRadius.circular(999),
                        ),
                        child: Text(
                          data.badge.toString(),
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.onError,
                            fontSize: 11,
                            fontWeight: FontWeight.w900,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      data.title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontWeight: FontWeight.w900),
                    ),
                    Text(
                      data.subtitle,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
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

class _ChatTile extends StatelessWidget {
  final Color accent;
  final String title;
  final String subtitle;
  final String? avatarUrl;
  final bool isGroup;
  final VoidCallback onTap;

  const _ChatTile({
    required this.accent,
    required this.title,
    required this.subtitle,
    required this.avatarUrl,
    required this.isGroup,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final normalizedAvatar =
        avatarUrl == null || avatarUrl!.trim().isEmpty ? null : avatarUrl;

    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surface.withValues(alpha: 0.82),
      margin: const EdgeInsets.symmetric(vertical: 5),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: BorderSide(
          color: accent.withValues(alpha: 0.16),
        ),
      ),
      child: ListTile(
        onTap: onTap,
        contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        leading: CircleAvatar(
          radius: 25,
          backgroundColor: accent.withValues(alpha: 0.18),
          backgroundImage: normalizedAvatar == null
              ? null
              : NetworkImage(ApiClient.absoluteUrl(normalizedAvatar)),
          child: normalizedAvatar == null
              ? isGroup
                  ? Icon(
                      Icons.groups_2_outlined,
                      color: accent,
                    )
                  : Text(
                      title.isNotEmpty ? title.characters.first.toUpperCase() : '?',
                      style: TextStyle(
                        color: accent,
                        fontWeight: FontWeight.w900,
                      ),
                    )
              : null,
        ),
        title: Text(
          title,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(fontWeight: FontWeight.w800),
        ),
        subtitle: Text(
          subtitle,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        trailing: Icon(
          Icons.chevron_right,
          color: accent,
        ),
      ),
    );
  }
}

class _RequestsSummaryCard extends StatelessWidget {
  final Color accent;
  final int incomingCount;
  final int outgoingCount;
  final VoidCallback onTap;

  const _RequestsSummaryCard({
    required this.accent,
    required this.incomingCount,
    required this.outgoingCount,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final parts = <String>[];

    if (incomingCount > 0) {
      parts.add('входящие: $incomingCount');
    }

    if (outgoingCount > 0) {
      parts.add('исходящие: $outgoingCount');
    }

    return Card(
      elevation: 0,
      color: accent.withValues(alpha: 0.12),
      margin: const EdgeInsets.only(bottom: 12),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(22),
        side: BorderSide(color: accent.withValues(alpha: 0.25)),
      ),
      child: ListTile(
        onTap: onTap,
        leading: CircleAvatar(
          backgroundColor: accent.withValues(alpha: 0.18),
          child: Icon(
            Icons.mark_email_unread_outlined,
            color: accent,
          ),
        ),
        title: const Text('Запросы на чат'),
        subtitle: Text(parts.join(', ')),
        trailing: Icon(Icons.chevron_right, color: accent),
      ),
    );
  }
}

class _EmptyChatsCard extends StatelessWidget {
  final Color accent;

  const _EmptyChatsCard({required this.accent});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: 420,
      child: Center(
        child: Card(
          elevation: 0,
          color: Theme.of(context).colorScheme.surface.withValues(alpha: 0.82),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(26),
            side: BorderSide(color: accent.withValues(alpha: 0.2)),
          ),
          child: Padding(
            padding: const EdgeInsets.all(22),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.forum_outlined,
                  size: 56,
                  color: accent,
                ),
                const SizedBox(height: 12),
                Text(
                  'Пока нет чатов',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 6),
                Text(
                  'Нажмите “Найти”, чтобы отправить запрос пользователю',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ],
            ),
          ),
        ),
      ),
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


class _MobileSideMenu extends StatelessWidget {
  final String name;
  final Color accent;
  final int incomingCount;
  final int outgoingCount;
  final bool notificationsEnabled;
  final bool refreshing;

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
    required this.refreshing,
    required this.onFindUser,
    required this.onCreateGroup,
    required this.onRequests,
    required this.onSettings,
    required this.onRefresh,
    required this.onEnablePush,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final width = MediaQuery.of(context).size.width;
    final panelWidth = width < 430 ? width * 0.86 : 350.0;
    final isDark = theme.brightness == Brightness.dark;
    final surface = isDark ? const Color(0xFF101923) : const Color(0xFFF7FAFC);

    return ClipRRect(
      borderRadius: const BorderRadius.horizontal(
        right: Radius.circular(28),
      ),
      child: BackdropFilter(
        filter: ImageFilter.blur(
          sigmaX: 18,
          sigmaY: 18,
        ),
        child: Container(
          width: panelWidth,
          height: double.infinity,
          decoration: BoxDecoration(
            color: surface.withValues(alpha: 0.985),
            border: Border(
              right: BorderSide(
                color: accent.withValues(alpha: 0.22),
              ),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.34),
                blurRadius: 34,
                offset: const Offset(14, 0),
              ),
            ],
          ),
          child: SafeArea(
            right: false,
            child: Column(
              children: [
                _MobileSideHeader(
                  name: name,
                  accent: accent,
                  notificationsEnabled: notificationsEnabled,
                ),
                Expanded(
                  child: ListView(
                    padding: EdgeInsets.zero,
                    children: [
                      _MobileAccountTile(
                        name: name,
                        accent: accent,
                        selected: true,
                      ),
                      _MobileMenuItem(
                        icon: Icons.add_circle_outline_rounded,
                        title: 'Добавить контакт',
                        subtitle: 'найти пользователя и начать чат',
                        onTap: onFindUser,
                      ),
                      const _MobileMenuDivider(),
                      _MobileMenuItem(
                        icon: Icons.group_add_rounded,
                        title: 'Создать группу',
                        subtitle: 'новый групповой чат',
                        onTap: onCreateGroup,
                      ),
                      _MobileMenuItem(
                        icon: Icons.mark_email_unread_rounded,
                        title: 'Запросы',
                        subtitle: _requestsSubtitle(),
                        badge: incomingCount > 0 ? incomingCount.toString() : null,
                        onTap: onRequests,
                      ),
                      if (!notificationsEnabled)
                        _MobileMenuItem(
                          icon: Icons.notifications_active_rounded,
                          title: 'Включить Push',
                          subtitle: 'уведомления о сообщениях',
                          onTap: onEnablePush,
                        ),
                      const _MobileMenuDivider(),
                      _MobileMenuItem(
                        icon: Icons.person_outline_rounded,
                        title: 'Мой профиль',
                        subtitle: 'имя, аватар и статус',
                        onTap: onSettings,
                      ),
                      _MobileMenuItem(
                        icon: Icons.settings_rounded,
                        title: 'Настройки',
                        subtitle: 'тема и внешний вид',
                        onTap: onSettings,
                      ),
                      _MobileMenuItem(
                        icon: Icons.refresh_rounded,
                        title: refreshing ? 'Обновление...' : 'Обновить',
                        subtitle: 'перезагрузить список чатов',
                        onTap: refreshing ? null : onRefresh,
                      ),
                    ],
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(18, 8, 18, 18),
                  child: Row(
                    children: [
                      Icon(
                        Icons.lock_outline_rounded,
                        size: 17,
                        color: theme.colorScheme.onSurface.withValues(alpha: 0.50),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'UMe private messenger',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurface.withValues(alpha: 0.50),
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
        ),
      ),
    );
  }

  String _requestsSubtitle() {
    if (incomingCount > 0 && outgoingCount > 0) {
      return 'входящие: $incomingCount · исходящие: $outgoingCount';
    }

    if (incomingCount > 0) {
      return 'входящие: $incomingCount';
    }

    if (outgoingCount > 0) {
      return 'исходящие: $outgoingCount';
    }

    return 'нет активных запросов';
  }
}

class _MobileSideHeader extends StatelessWidget {
  final String name;
  final Color accent;
  final bool notificationsEnabled;

  const _MobileSideHeader({
    required this.name,
    required this.accent,
    required this.notificationsEnabled,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            accent.withValues(alpha: 0.96),
            accent.withValues(alpha: 0.68),
            const Color(0xFF0F172A),
          ],
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            radius: 34,
            backgroundColor: Colors.white.withValues(alpha: 0.20),
            foregroundColor: Colors.white,
            child: Text(
              name.isNotEmpty ? name.characters.first.toUpperCase() : 'U',
              style: const TextStyle(
                fontSize: 28,
                fontWeight: FontWeight.w900,
              ),
            ),
          ),
          const SizedBox(height: 14),
          Text(
            name,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.titleMedium?.copyWith(
              color: Colors.white,
              fontWeight: FontWeight.w900,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            notificationsEnabled ? 'Push-уведомления включены' : 'Push-уведомления не включены',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: Colors.white.withValues(alpha: 0.78),
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class _MobileAccountTile extends StatelessWidget {
  final String name;
  final Color accent;
  final bool selected;

  const _MobileAccountTile({
    required this.name,
    required this.accent,
    required this.selected,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 6),
      leading: CircleAvatar(
        backgroundColor: accent.withValues(alpha: 0.17),
        foregroundColor: accent,
        child: Text(
          name.isNotEmpty ? name.characters.first.toUpperCase() : 'U',
          style: const TextStyle(fontWeight: FontWeight.w900),
        ),
      ),
      title: Text(
        name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontWeight: FontWeight.w900),
      ),
      subtitle: const Text('текущий аккаунт'),
      trailing: selected
          ? Container(
              width: 11,
              height: 11,
              decoration: BoxDecoration(
                color: accent,
                shape: BoxShape.circle,
              ),
            )
          : null,
    );
  }
}

class _MobileMenuItem extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final String? badge;
  final VoidCallback? onTap;

  const _MobileMenuItem({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.badge,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final disabled = onTap == null;
    final accent = theme.colorScheme.primary;
    final textColor = theme.colorScheme.onSurface.withValues(alpha: disabled ? 0.38 : 0.90);

    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(18, 8, 14, 8),
        child: Row(
          children: [
            Icon(
              icon,
              size: 25,
              color: theme.colorScheme.onSurface.withValues(alpha: disabled ? 0.32 : 0.82),
            ),
            const SizedBox(width: 18),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodyLarge?.copyWith(
                      color: textColor,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurface.withValues(alpha: disabled ? 0.28 : 0.54),
                    ),
                  ),
                ],
              ),
            ),
            if (badge != null)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: accent,
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  badge!,
                  style: TextStyle(
                    color: accent.computeLuminance() > 0.55 ? Colors.black : Colors.white,
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

class _MobileMenuDivider extends StatelessWidget {
  const _MobileMenuDivider();

  @override
  Widget build(BuildContext context) {
    return Divider(
      height: 18,
      thickness: 1,
      color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.08),
    );
  }
}


