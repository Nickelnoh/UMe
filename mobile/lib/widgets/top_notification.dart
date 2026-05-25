import 'dart:async';

import 'package:flutter/material.dart';

enum TopNotificationType {
  success,
  error,
  warning,
  info,
  message,
}

class TopNotification {
  static OverlayEntry? _currentEntry;
  static Timer? _timer;

  static void show(
    BuildContext context, {
    required String message,
    String? title,
    TopNotificationType type = TopNotificationType.info,
    Duration duration = const Duration(seconds: 3),
  }) {
    _timer?.cancel();
    _currentEntry?.remove();
    _currentEntry = null;

    final overlay = Overlay.maybeOf(context);
    if (overlay == null) return;

    final theme = Theme.of(context);
    final colors = _colors(type, theme);
    final icon = _icon(type);

    final entry = OverlayEntry(
      builder: (context) {
        return _TopNotificationWidget(
          title: title,
          message: message,
          icon: icon,
          backgroundColor: colors.background,
          foregroundColor: colors.foreground,
          borderColor: colors.border,
          onClose: hide,
        );
      },
    );

    _currentEntry = entry;
    overlay.insert(entry);

    _timer = Timer(duration, hide);
  }

  static void success(
    BuildContext context, {
    required String message,
    String? title,
  }) {
    show(
      context,
      title: title ?? 'Готово',
      message: message,
      type: TopNotificationType.success,
    );
  }

  static void error(
    BuildContext context, {
    required String message,
    String? title,
  }) {
    show(
      context,
      title: title ?? 'Ошибка',
      message: message,
      type: TopNotificationType.error,
      duration: const Duration(seconds: 4),
    );
  }

  static void warning(
    BuildContext context, {
    required String message,
    String? title,
  }) {
    show(
      context,
      title: title ?? 'Внимание',
      message: message,
      type: TopNotificationType.warning,
    );
  }

  static void info(
    BuildContext context, {
    required String message,
    String? title,
  }) {
    show(
      context,
      title: title ?? 'Информация',
      message: message,
      type: TopNotificationType.info,
    );
  }

  static void message(
    BuildContext context, {
    required String message,
    String? title,
  }) {
    show(
      context,
      title: title ?? 'Новое сообщение',
      message: message,
      type: TopNotificationType.message,
    );
  }

  static void hide() {
    _timer?.cancel();
    _timer = null;

    _currentEntry?.remove();
    _currentEntry = null;
  }

  static IconData _icon(TopNotificationType type) {
    switch (type) {
      case TopNotificationType.success:
        return Icons.check_circle_outline;
      case TopNotificationType.error:
        return Icons.error_outline;
      case TopNotificationType.warning:
        return Icons.warning_amber_rounded;
      case TopNotificationType.info:
        return Icons.info_outline;
      case TopNotificationType.message:
        return Icons.chat_bubble_outline;
    }
  }

  static _NotificationColors _colors(
    TopNotificationType type,
    ThemeData theme,
  ) {
    final isDark = theme.brightness == Brightness.dark;

    switch (type) {
      case TopNotificationType.success:
        return _NotificationColors(
          background:
              isDark ? const Color(0xFF062E1A) : const Color(0xFFE8F8EF),
          foreground:
              isDark ? const Color(0xFF9CF2BD) : const Color(0xFF116B37),
          border: isDark ? const Color(0xFF1B7A43) : const Color(0xFF9ADBB3),
        );

      case TopNotificationType.error:
        return _NotificationColors(
          background:
              isDark ? const Color(0xFF3A0B0B) : const Color(0xFFFFECEC),
          foreground:
              isDark ? const Color(0xFFFFA7A7) : const Color(0xFFB42318),
          border: isDark ? const Color(0xFF8A2424) : const Color(0xFFFFB4B4),
        );

      case TopNotificationType.warning:
        return _NotificationColors(
          background:
              isDark ? const Color(0xFF332400) : const Color(0xFFFFF6DF),
          foreground:
              isDark ? const Color(0xFFFFD36A) : const Color(0xFF946200),
          border: isDark ? const Color(0xFF7A570A) : const Color(0xFFFFD887),
        );

      case TopNotificationType.message:
        return _NotificationColors(
          background:
              isDark ? const Color(0xFF101A3D) : const Color(0xFFECEFFF),
          foreground:
              isDark ? const Color(0xFFAEBBFF) : const Color(0xFF3547A0),
          border: isDark ? const Color(0xFF36478F) : const Color(0xFFB8C1FF),
        );

      case TopNotificationType.info:
        return _NotificationColors(
          background:
              isDark ? const Color(0xFF111827) : const Color(0xFFF2F4F7),
          foreground:
              isDark ? const Color(0xFFD0D5DD) : const Color(0xFF344054),
          border: isDark ? const Color(0xFF344054) : const Color(0xFFD0D5DD),
        );
    }
  }
}

class _TopNotificationWidget extends StatefulWidget {
  final String? title;
  final String message;
  final IconData icon;
  final Color backgroundColor;
  final Color foregroundColor;
  final Color borderColor;
  final VoidCallback onClose;

  const _TopNotificationWidget({
    required this.title,
    required this.message,
    required this.icon,
    required this.backgroundColor,
    required this.foregroundColor,
    required this.borderColor,
    required this.onClose,
  });

  @override
  State<_TopNotificationWidget> createState() => _TopNotificationWidgetState();
}

class _TopNotificationWidgetState extends State<_TopNotificationWidget>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<Offset> _slideAnimation;
  late final Animation<double> _fadeAnimation;
  late final Animation<double> _scaleAnimation;

  @override
  void initState() {
    super.initState();

    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 260),
      reverseDuration: const Duration(milliseconds: 180),
    );

    _slideAnimation = Tween<Offset>(
      begin: const Offset(0, -0.8),
      end: Offset.zero,
    ).animate(
      CurvedAnimation(
        parent: _controller,
        curve: Curves.easeOutCubic,
        reverseCurve: Curves.easeInCubic,
      ),
    );

    _fadeAnimation = CurvedAnimation(
      parent: _controller,
      curve: Curves.easeOut,
      reverseCurve: Curves.easeIn,
    );

    _scaleAnimation = Tween<double>(
      begin: 0.96,
      end: 1,
    ).animate(
      CurvedAnimation(
        parent: _controller,
        curve: Curves.easeOutBack,
        reverseCurve: Curves.easeIn,
      ),
    );

    _controller.forward();
  }

  Future<void> _close() async {
    if (!mounted) return;

    await _controller.reverse();
    widget.onClose();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final topPadding = MediaQuery.of(context).padding.top;

    return Positioned(
      top: topPadding + 14,
      left: 12,
      right: 12,
      child: SafeArea(
        top: false,
        child: SlideTransition(
          position: _slideAnimation,
          child: FadeTransition(
            opacity: _fadeAnimation,
            child: ScaleTransition(
              scale: _scaleAnimation,
              child: Center(
                child: Material(
                  color: Colors.transparent,
                  child: GestureDetector(
                    onTap: _close,
                    onVerticalDragEnd: (details) {
                      if ((details.primaryVelocity ?? 0) < -150) {
                        _close();
                      }
                    },
                    child: Container(
                      constraints: const BoxConstraints(maxWidth: 620),
                      margin: const EdgeInsets.symmetric(horizontal: 4),
                      padding: const EdgeInsets.fromLTRB(14, 12, 8, 12),
                      decoration: BoxDecoration(
                        color: widget.backgroundColor,
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                          color: widget.borderColor,
                          width: 1,
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: 0.18),
                            blurRadius: 24,
                            offset: const Offset(0, 10),
                          ),
                        ],
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            width: 38,
                            height: 38,
                            decoration: BoxDecoration(
                              color: widget.foregroundColor.withValues(
                                alpha: 0.12,
                              ),
                              borderRadius: BorderRadius.circular(14),
                            ),
                            child: Icon(
                              widget.icon,
                              color: widget.foregroundColor,
                              size: 22,
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Padding(
                              padding: const EdgeInsets.only(top: 1),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  if (widget.title != null &&
                                      widget.title!.trim().isNotEmpty)
                                    Text(
                                      widget.title!,
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                      style: TextStyle(
                                        color: widget.foregroundColor,
                                        fontSize: 14,
                                        fontWeight: FontWeight.w800,
                                      ),
                                    ),
                                  if (widget.title != null &&
                                      widget.title!.trim().isNotEmpty)
                                    const SizedBox(height: 3),
                                  Text(
                                    widget.message,
                                    maxLines: 3,
                                    overflow: TextOverflow.ellipsis,
                                    style: TextStyle(
                                      color: widget.foregroundColor.withValues(
                                        alpha: 0.9,
                                      ),
                                      fontSize: 13.5,
                                      fontWeight: FontWeight.w500,
                                      height: 1.25,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          IconButton(
                            visualDensity: VisualDensity.compact,
                            onPressed: _close,
                            icon: Icon(
                              Icons.close,
                              color: widget.foregroundColor.withValues(
                                alpha: 0.75,
                              ),
                              size: 20,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _NotificationColors {
  final Color background;
  final Color foreground;
  final Color border;

  const _NotificationColors({
    required this.background,
    required this.foreground,
    required this.border,
  });
}