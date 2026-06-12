import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../app.dart';
import '../../core/api_client.dart';
import '../../widgets/top_notification.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _loading = true;
  bool _saving = false;

  String _username = '';
  String _nickname = '';
  String _displayName = '';
  String? _avatarUrl;

  String _theme = 'system';
  String _accentColor = '#075E54';
  String _chatWallpaper = 'default';
  String _bubbleStyle = 'rounded';

  final _nicknameController = TextEditingController();
  final _displayNameController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadMe();
  }

  @override
  void dispose() {
    _nicknameController.dispose();
    _displayNameController.dispose();
    super.dispose();
  }

  Future<void> _loadMe() async {
    if (mounted) setState(() => _loading = true);

    try {
      final me = await ApiClient.get('/me');

      if (!mounted) return;

      final nextTheme = me['theme']?.toString() ?? 'system';
      final nextAccent = me['accent_color']?.toString() ?? '#075E54';

      themeModeNotifier.value = parseUmeThemeMode(nextTheme);
      accentColorNotifier.value = parseUmeAccentColor(nextAccent);

      setState(() {
        _username = me['username']?.toString() ?? '';
        _nickname = me['nickname']?.toString() ?? '';
        _displayName = me['display_name']?.toString() ?? '';
        _avatarUrl = me['avatar_url']?.toString();

        _theme = nextTheme;
        _accentColor = nextAccent;
        _chatWallpaper = me['chat_wallpaper']?.toString() ?? 'default';
        _bubbleStyle = me['bubble_style']?.toString() ?? 'rounded';

        _nicknameController.text = _nickname;
        _displayNameController.text = _displayName;
      });
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _saveProfile() async {
    final nickname = _nicknameController.text.trim();
    final displayName = _displayNameController.text.trim();

    if (nickname.length < 2) {
      _showError('Никнейм должен быть минимум 2 символа');
      return;
    }

    if (displayName.isNotEmpty && displayName.length < 2) {
      _showError('Имя должно быть минимум 2 символа');
      return;
    }

    setState(() => _saving = true);

    try {
      await ApiClient.post(
        '/profile',
        {
          'nickname': nickname,
          'display_name': displayName.isEmpty ? nickname : displayName,
        },
      );

      if (!mounted) return;
      TopNotification.success(context, message: 'Профиль сохранён');
      await _loadMe();
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _saveTheme(String value) async {
    setState(() {
      _theme = value;
      _saving = true;
    });

    themeModeNotifier.value = parseUmeThemeMode(value);

    try {
      await ApiClient.post('/settings/theme', {'theme': value});
      if (!mounted) return;
      TopNotification.success(context, message: 'Тема сохранена');
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _saveChatAppearance({
    String? accentColor,
    String? chatWallpaper,
    String? bubbleStyle,
  }) async {
    final nextAccent = accentColor ?? _accentColor;
    final nextWallpaper = chatWallpaper ?? _chatWallpaper;
    final nextBubble = bubbleStyle ?? _bubbleStyle;

    setState(() {
      _accentColor = nextAccent;
      _chatWallpaper = nextWallpaper;
      _bubbleStyle = nextBubble;
      _saving = true;
    });

    accentColorNotifier.value = parseUmeAccentColor(nextAccent);

    try {
      await ApiClient.post(
        '/settings/chat-appearance',
        {
          'accent_color': nextAccent,
          'chat_wallpaper': nextWallpaper,
          'bubble_style': nextBubble,
        },
      );

      if (!mounted) return;
      TopNotification.success(context, message: 'Вид сообщений сохранён');
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _pickAvatar() async {
    try {
      final result = await FilePicker.pickFiles(
        withData: true,
        allowMultiple: false,
        type: FileType.image,
      );

      if (result == null || result.files.isEmpty) return;

      final file = result.files.first;
      if (file.bytes == null) {
        _showError('Не удалось прочитать изображение');
        return;
      }

      setState(() => _saving = true);

      final response = await ApiClient.uploadBytes(
        path: '/profile/avatar',
        bytes: file.bytes!,
        filename: file.name,
      );

      if (!mounted) return;
      setState(() => _avatarUrl = response['url']?.toString());
      TopNotification.success(context, message: 'Аватар обновлён');
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _pickChatWallpaperImage() async {
    try {
      final result = await FilePicker.pickFiles(
        withData: true,
        allowMultiple: false,
        type: FileType.image,
      );

      if (result == null || result.files.isEmpty) return;

      final file = result.files.first;
      if (file.bytes == null) {
        _showError('Не удалось прочитать изображение');
        return;
      }

      setState(() => _saving = true);

      final response = await ApiClient.uploadBytes(
        path: '/settings/chat-wallpaper-image',
        bytes: file.bytes!,
        filename: file.name,
      );

      final wallpaperUrl = response['wallpaper_url']?.toString();
      if (wallpaperUrl == null || wallpaperUrl.isEmpty) {
        throw Exception('Сервер не вернул wallpaper_url');
      }

      if (!mounted) return;
      setState(() => _chatWallpaper = wallpaperUrl);
      TopNotification.success(context, message: 'Фон сообщений обновлён');
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  String _cleanError(Object e) {
    var text = e.toString();
    text = text.replaceFirst('Exception: ', '');

    if (text.contains('Failed to fetch')) return 'Не удалось подключиться к серверу';
    if (text.contains('TimeoutException')) return 'Сервер не ответил вовремя';
    if (text.contains('Nickname already exists')) return 'Никнейм уже занят';

    return text;
  }

  void _showError(String message) {
    if (!mounted) return;
    TopNotification.error(context, message: message);
  }

  Color _accentColorValue(String value) => parseUmeAccentColor(value);

  String _colorToHex(Color color) {
    final value = color.toARGB32() & 0x00FFFFFF;
    return '#${value.toRadixString(16).padLeft(6, '0').toUpperCase()}';
  }

  Future<void> _openAccentColorPicker() async {
    final initialColor = _accentColorValue(_accentColor);

    final selected = await showModalBottomSheet<Color>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (_) => _AccentColorPickerSheet(initialColor: initialColor),
    );

    if (selected == null) return;

    await _saveChatAppearance(accentColor: _colorToHex(selected));
  }

  bool get _isCustomWallpaper {
    return _chatWallpaper.startsWith('/uploads/') ||
        _chatWallpaper.startsWith('http://') ||
        _chatWallpaper.startsWith('https://');
  }

  String _themeLabel(String value) {
    switch (value) {
      case 'light':
        return 'Светлая';
      case 'dark':
        return 'Тёмная';
      case 'system':
      default:
        return 'Как в системе';
    }
  }

  String _wallpaperLabel(String value) {
    if (_isCustomWallpaper) return 'Своя картинка';

    switch (value) {
      case 'clean':
        return 'Чистый';
      case 'gradient':
        return 'Градиент';
      case 'night':
        return 'Ночь';
      case 'mint':
        return 'Мята';
      case 'default':
      default:
        return 'Обычный';
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final accent = _accentColorValue(_accentColor);
    final avatar = _avatarUrl == null || _avatarUrl!.isEmpty
        ? null
        : ApiClient.absoluteUrl(_avatarUrl);

    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : Column(
              children: [
                _OldWhatsSettingsHeader(
                  title: 'Настройки',
                  subtitle: _username.isEmpty ? 'UMe' : '@$_username',
                  accent: accent,
                  onBack: () => Navigator.of(context).pop(),
                ),
                Expanded(
                  child: SafeArea(
                    top: false,
                    child: ListView(
                      padding: const EdgeInsets.fromLTRB(12, 12, 12, 28),
                      children: [
                        _OldWhatsSettingsSection(
                          title: 'Профиль',
                          children: [
                            _ProfileTile(
                              avatarUrl: avatar,
                              name: _displayName.isNotEmpty ? _displayName : _nickname,
                              username: _username,
                              accent: accent,
                              onAvatarTap: _saving ? null : _pickAvatar,
                            ),
                            const SizedBox(height: 12),
                            TextField(
                              controller: _nicknameController,
                              enabled: !_saving,
                              decoration: const InputDecoration(
                                labelText: 'Никнейм',
                                prefixIcon: Icon(Icons.badge_outlined),
                              ),
                            ),
                            const SizedBox(height: 10),
                            TextField(
                              controller: _displayNameController,
                              enabled: !_saving,
                              decoration: const InputDecoration(
                                labelText: 'Отображаемое имя',
                                prefixIcon: Icon(Icons.person_outline),
                              ),
                            ),
                            const SizedBox(height: 12),
                            FilledButton.icon(
                              onPressed: _saving ? null : _saveProfile,
                              icon: const Icon(Icons.save_outlined),
                              label: const Text('Сохранить профиль'),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        _OldWhatsSettingsSection(
                          title: 'Настройки приложения',
                          children: [
                            _SettingsInfoTile(
                              icon: Icons.dark_mode_outlined,
                              title: 'Тема',
                              subtitle: _themeLabel(_theme),
                              accent: accent,
                            ),
                            const SizedBox(height: 10),
                            _ChoiceRow<String>(
                              selected: _theme,
                              enabled: !_saving,
                              values: const ['system', 'light', 'dark'],
                              labels: const {
                                'system': 'Система',
                                'light': 'Светлая',
                                'dark': 'Тёмная',
                              },
                              onChanged: _saveTheme,
                            ),
                            const SizedBox(height: 14),
                            _SettingsInfoTile(
                              icon: Icons.notifications_none_rounded,
                              title: 'Уведомления',
                              subtitle: 'Push включается на главном экране',
                              accent: accent,
                            ),
                            _SettingsInfoTile(
                              icon: Icons.lock_outline_rounded,
                              title: 'Приватность',
                              subtitle: 'Личные чаты и приватный доступ',
                              accent: accent,
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        _OldWhatsSettingsSection(
                          title: 'Внешний вид сообщений',
                          children: [
                            _SettingsInfoTile(
                              icon: Icons.palette_outlined,
                              title: 'Акцентный цвет',
                              subtitle: _colorToHex(accent),
                              accent: accent,
                              trailing: Container(
                                width: 32,
                                height: 32,
                                decoration: BoxDecoration(
                                  color: accent,
                                  shape: BoxShape.circle,
                                  border: Border.all(
                                    color: isDark ? Colors.white24 : Colors.black12,
                                  ),
                                ),
                              ),
                              onTap: _saving ? null : _openAccentColorPicker,
                            ),
                            const SizedBox(height: 12),
                            _SettingsInfoTile(
                              icon: Icons.chat_bubble_outline_rounded,
                              title: 'Стиль сообщений',
                              subtitle: _bubbleStyle,
                              accent: accent,
                            ),
                            const SizedBox(height: 10),
                            _ChoiceRow<String>(
                              selected: _bubbleStyle,
                              enabled: !_saving,
                              values: const ['rounded', 'soft', 'compact'],
                              labels: const {
                                'rounded': 'Круглый',
                                'soft': 'Мягкий',
                                'compact': 'Компакт',
                              },
                              onChanged: (value) => _saveChatAppearance(bubbleStyle: value),
                            ),
                            const SizedBox(height: 18),
                            _SettingsInfoTile(
                              icon: Icons.image_outlined,
                              title: 'Фон сообщений',
                              subtitle: _wallpaperLabel(_chatWallpaper),
                              accent: accent,
                            ),
                            const SizedBox(height: 10),
                            _WallpaperOptionTile(
                              title: 'Обычный',
                              subtitle: 'Светлый классический фон',
                              value: 'default',
                              selected: _chatWallpaper == 'default',
                              accent: accent,
                              onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'default'),
                            ),
                            _WallpaperOptionTile(
                              title: 'Чистый',
                              subtitle: 'Без лишнего рисунка',
                              value: 'clean',
                              selected: _chatWallpaper == 'clean',
                              accent: accent,
                              onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'clean'),
                            ),
                            _WallpaperOptionTile(
                              title: 'Градиент',
                              subtitle: 'Мягкий цветовой переход',
                              value: 'gradient',
                              selected: _chatWallpaper == 'gradient',
                              accent: accent,
                              onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'gradient'),
                            ),
                            _WallpaperOptionTile(
                              title: 'Ночь',
                              subtitle: 'Тёмный фон сообщений',
                              value: 'night',
                              selected: _chatWallpaper == 'night',
                              accent: accent,
                              onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'night'),
                            ),
                            _WallpaperOptionTile(
                              title: 'Мята',
                              subtitle: 'Светлый зелёный оттенок',
                              value: 'mint',
                              selected: _chatWallpaper == 'mint',
                              accent: accent,
                              onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'mint'),
                            ),
                            const SizedBox(height: 8),
                            OutlinedButton.icon(
                              onPressed: _saving ? null : _pickChatWallpaperImage,
                              icon: const Icon(Icons.add_photo_alternate_outlined),
                              label: Text(
                                _isCustomWallpaper ? 'Заменить свою картинку' : 'Поставить свою картинку',
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
    );
  }
}

class _OldWhatsSettingsHeader extends StatelessWidget {
  final String title;
  final String subtitle;
  final Color accent;
  final VoidCallback onBack;

  const _OldWhatsSettingsHeader({
    required this.title,
    required this.subtitle,
    required this.accent,
    required this.onBack,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [accent, HSLColor.fromColor(accent).withLightness(0.40).toColor()],
        ),
      ),
      child: SafeArea(
        bottom: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(4, 8, 12, 12),
          child: Row(
            children: [
              IconButton(
                onPressed: onBack,
                icon: const Icon(Icons.arrow_back_rounded),
                color: Colors.white,
              ),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 21,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      style: TextStyle(
                        color: Colors.white.withValues(alpha: 0.80),
                        fontWeight: FontWeight.w700,
                      ),
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

class _OldWhatsSettingsSection extends StatelessWidget {
  final String title;
  final List<Widget> children;

  const _OldWhatsSettingsSection({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return DecoratedBox(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: theme.dividerColor.withValues(alpha: 0.6)),
      ),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              title.toUpperCase(),
              style: TextStyle(
                color: theme.colorScheme.primary,
                fontSize: 12,
                fontWeight: FontWeight.w900,
                letterSpacing: 0.8,
              ),
            ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }
}

class _ProfileTile extends StatelessWidget {
  final String? avatarUrl;
  final String name;
  final String username;
  final Color accent;
  final VoidCallback? onAvatarTap;

  const _ProfileTile({
    required this.avatarUrl,
    required this.name,
    required this.username,
    required this.accent,
    required this.onAvatarTap,
  });

  @override
  Widget build(BuildContext context) {
    final title = name.trim().isEmpty ? 'UMe user' : name.trim();

    return Row(
      children: [
        InkWell(
          onTap: onAvatarTap,
          customBorder: const CircleBorder(),
          child: Stack(
            clipBehavior: Clip.none,
            children: [
              CircleAvatar(
                radius: 34,
                backgroundColor: accent.withValues(alpha: 0.16),
                backgroundImage: avatarUrl == null ? null : NetworkImage(avatarUrl!),
                foregroundColor: accent,
                child: avatarUrl == null
                    ? Text(
                        title.characters.first.toUpperCase(),
                        style: const TextStyle(fontSize: 28, fontWeight: FontWeight.w900),
                      )
                    : null,
              ),
              Positioned(
                right: -2,
                bottom: -2,
                child: CircleAvatar(
                  radius: 13,
                  backgroundColor: accent,
                  foregroundColor: Colors.white,
                  child: const Icon(Icons.photo_camera_outlined, size: 15),
                ),
              ),
            ],
          ),
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
                style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w900),
              ),
              if (username.isNotEmpty)
                Text(
                  '@$username',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.62),
                    fontWeight: FontWeight.w600,
                  ),
                ),
            ],
          ),
        ),
      ],
    );
  }
}

class _SettingsInfoTile extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final Color accent;
  final Widget? trailing;
  final VoidCallback? onTap;

  const _SettingsInfoTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.accent,
    this.trailing,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(
            children: [
              Icon(icon, color: accent, size: 25),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w900),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      style: TextStyle(
                        color: theme.colorScheme.onSurface.withValues(alpha: 0.58),
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
              if (trailing != null) trailing!,
            ],
          ),
        ),
      ),
    );
  }
}

class _ChoiceRow<T> extends StatelessWidget {
  final T selected;
  final bool enabled;
  final List<T> values;
  final Map<T, String> labels;
  final ValueChanged<T> onChanged;

  const _ChoiceRow({
    required this.selected,
    required this.enabled,
    required this.values,
    required this.labels,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accent = theme.colorScheme.primary;

    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: values.map((value) {
        final isSelected = value == selected;

        return ChoiceChip(
          selected: isSelected,
          label: Text(labels[value] ?? value.toString()),
          onSelected: enabled ? (_) => onChanged(value) : null,
          selectedColor: accent.withValues(alpha: 0.18),
          checkmarkColor: accent,
          side: BorderSide(
            color: isSelected ? accent : theme.dividerColor,
          ),
          labelStyle: TextStyle(
            color: isSelected ? accent : theme.colorScheme.onSurface,
            fontWeight: FontWeight.w800,
          ),
        );
      }).toList(),
    );
  }
}

class _WallpaperOptionTile extends StatelessWidget {
  final String title;
  final String subtitle;
  final String value;
  final bool selected;
  final Color accent;
  final VoidCallback? onTap;

  const _WallpaperOptionTile({
    required this.title,
    required this.subtitle,
    required this.value,
    required this.selected,
    required this.accent,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(9),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 160),
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: selected ? accent.withValues(alpha: 0.11) : theme.colorScheme.surface,
            borderRadius: BorderRadius.circular(9),
            border: Border.all(
              color: selected ? accent : theme.dividerColor,
            ),
          ),
          child: Row(
            children: [
              _WallpaperMiniPreview(value: value, accent: accent),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: const TextStyle(fontWeight: FontWeight.w900, fontSize: 15.5),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      style: TextStyle(
                        color: theme.colorScheme.onSurface.withValues(alpha: 0.58),
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
              if (selected)
                Icon(Icons.check_circle_rounded, color: accent),
            ],
          ),
        ),
      ),
    );
  }
}

class _WallpaperMiniPreview extends StatelessWidget {
  final String value;
  final Color accent;

  const _WallpaperMiniPreview({required this.value, required this.accent});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 46,
      height: 46,
      decoration: _decoration(context),
      child: Stack(
        children: [
          Positioned(
            left: 6,
            top: 9,
            child: Container(
              width: 20,
              height: 9,
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.85),
                borderRadius: BorderRadius.circular(999),
              ),
            ),
          ),
          Positioned(
            right: 6,
            bottom: 9,
            child: Container(
              width: 22,
              height: 9,
              decoration: BoxDecoration(
                color: accent.withValues(alpha: 0.80),
                borderRadius: BorderRadius.circular(999),
              ),
            ),
          ),
        ],
      ),
    );
  }

  BoxDecoration _decoration(BuildContext context) {
    switch (value) {
      case 'clean':
        return BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: Theme.of(context).dividerColor),
        );
      case 'gradient':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [accent.withValues(alpha: 0.42), Colors.white, accent.withValues(alpha: 0.18)],
          ),
        );
      case 'night':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          gradient: const LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF0F172A), Color(0xFF1E1B4B)],
          ),
        );
      case 'mint':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          gradient: const LinearGradient(
            colors: [Color(0xFFE8FFF5), Color(0xFFF6FFFB)],
          ),
        );
      case 'default':
      default:
        return BoxDecoration(
          color: const Color(0xFFECE5DD),
          borderRadius: BorderRadius.circular(10),
        );
    }
  }
}

class _AccentColorPickerSheet extends StatefulWidget {
  final Color initialColor;

  const _AccentColorPickerSheet({required this.initialColor});

  @override
  State<_AccentColorPickerSheet> createState() => _AccentColorPickerSheetState();
}

class _AccentColorPickerSheetState extends State<_AccentColorPickerSheet> {
  late double _hue;
  late double _saturation;
  late double _value;

  @override
  void initState() {
    super.initState();
    final hsv = HSVColor.fromColor(widget.initialColor);
    _hue = hsv.hue;
    _saturation = hsv.saturation;
    _value = hsv.value;
  }

  Color get _color => HSVColor.fromAHSV(1, _hue, _saturation, _value).toColor();

  String _hex(Color color) {
    final value = color.toARGB32() & 0x00FFFFFF;
    return '#${value.toRadixString(16).padLeft(6, '0').toUpperCase()}';
  }

  @override
  Widget build(BuildContext context) {
    final bottom = MediaQuery.of(context).viewInsets.bottom;
    final textColor = _color.computeLuminance() > 0.55 ? Colors.black : Colors.white;

    return Padding(
      padding: EdgeInsets.fromLTRB(18, 8, 18, bottom + 18),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Акцентный цвет',
              style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 14),
            AnimatedContainer(
              duration: const Duration(milliseconds: 140),
              height: 112,
              padding: const EdgeInsets.all(18),
              decoration: BoxDecoration(
                color: _color,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                children: [
                  Icon(Icons.color_lens_outlined, color: textColor, size: 34),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          'Будущий цвет',
                          style: TextStyle(color: textColor.withValues(alpha: 0.82), fontWeight: FontWeight.w700),
                        ),
                        Text(
                          _hex(_color),
                          style: TextStyle(
                            color: textColor,
                            fontSize: 24,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 1,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),
            _ColorSlider(
              label: 'Оттенок',
              value: _hue,
              min: 0,
              max: 360,
              onChanged: (value) => setState(() => _hue = value),
            ),
            _ColorSlider(
              label: 'Насыщенность',
              value: _saturation,
              min: 0,
              max: 1,
              onChanged: (value) => setState(() => _saturation = value),
            ),
            _ColorSlider(
              label: 'Яркость',
              value: _value,
              min: 0.15,
              max: 1,
              onChanged: (value) => setState(() => _value = value),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(null),
                    child: const Text('Отмена'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: () => Navigator.of(context).pop(_color),
                    icon: const Icon(Icons.check),
                    label: const Text('Применить'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _ColorSlider extends StatelessWidget {
  final String label;
  final double value;
  final double min;
  final double max;
  final ValueChanged<double> onChanged;

  const _ColorSlider({
    required this.label,
    required this.value,
    required this.min,
    required this.max,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(label, style: Theme.of(context).textTheme.labelLarge),
            ),
            Text(
              max == 360 ? value.round().toString() : '${(value * 100).round()}%',
              style: Theme.of(context).textTheme.labelMedium,
            ),
          ],
        ),
        Slider(value: value, min: min, max: max, onChanged: onChanged),
      ],
    );
  }
}
