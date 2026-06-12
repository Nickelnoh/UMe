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
  static const _green = Color(0xFF075E54);
  static const _lightGreen = Color(0xFF128C7E);
  static const _waBackground = Color(0xFFECE5DD);

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

      setState(() {
        _username = me['username']?.toString() ?? '';
        _nickname = me['nickname']?.toString() ?? '';
        _displayName = me['display_name']?.toString() ?? '';
        _avatarUrl = me['avatar_url']?.toString();

        _theme = me['theme']?.toString() ?? 'system';
        _accentColor = me['accent_color']?.toString() ?? '#075E54';
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

    themeModeNotifier.value = switch (value) {
      'light' => ThemeMode.light,
      'dark' => ThemeMode.dark,
      _ => ThemeMode.system,
    };

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
      TopNotification.success(context, message: 'Внешний вид сохранён');
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _pickAvatar() async {
    try {
      final result = await FilePicker.platform.pickFiles(
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
      final result = await FilePicker.platform.pickFiles(
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
      TopNotification.success(context, message: 'Фон чата обновлён');
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  String _cleanError(Object e) {
    var text = e.toString().replaceFirst('Exception: ', '');
    if (text.contains('Failed to fetch')) return 'Не удалось подключиться к серверу';
    if (text.contains('TimeoutException')) return 'Сервер не ответил вовремя';
    if (text.contains('Nickname already exists')) return 'Никнейм уже занят';
    return text;
  }

  void _showError(String message) {
    if (!mounted) return;
    TopNotification.error(context, message: message);
  }

  Color _accentColorValue(String value) {
    final parsed = _parseAccentColor(value);
    if (parsed != null) return parsed;

    switch (value) {
      case 'green':
        return _green;
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
    if (hex.length == 6) return Color(0xFF000000 | parsed);
    return Color(parsed);
  }

  String _colorToHex(Color color) {
    final value = color.toARGB32() & 0x00FFFFFF;
    return '#${value.toRadixString(16).padLeft(6, '0').toUpperCase()}';
  }

  Future<void> _openAccentColorPicker() async {
    final selected = await showModalBottomSheet<Color>(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (_) => _AccentColorPickerSheet(
        initialColor: _accentColorValue(_accentColor),
      ),
    );

    if (selected == null) return;
    await _saveChatAppearance(accentColor: _colorToHex(selected));
  }

  bool get _isCustomWallpaper {
    return _chatWallpaper.startsWith('/uploads/') ||
        _chatWallpaper.startsWith('http://') ||
        _chatWallpaper.startsWith('https://');
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final avatar = _avatarUrl == null || _avatarUrl!.isEmpty ? null : ApiClient.absoluteUrl(_avatarUrl);
    final name = _displayName.isNotEmpty ? _displayName : (_nickname.isNotEmpty ? _nickname : _username);

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF0B141A) : _waBackground,
      appBar: AppBar(
        title: const Text('Настройки'),
        backgroundColor: _green,
        foregroundColor: Colors.white,
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : SafeArea(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(0, 0, 0, 28),
                children: [
                  Container(
                    color: _green,
                    padding: const EdgeInsets.fromLTRB(18, 8, 18, 22),
                    child: Row(
                      children: [
                        Stack(
                          clipBehavior: Clip.none,
                          children: [
                            CircleAvatar(
                              radius: 36,
                              backgroundColor: Colors.white,
                              foregroundColor: _green,
                              backgroundImage: avatar == null ? null : NetworkImage(avatar),
                              child: avatar == null
                                  ? Text(
                                      name.isNotEmpty ? name.characters.first.toUpperCase() : 'U',
                                      style: const TextStyle(fontSize: 28, fontWeight: FontWeight.w900),
                                    )
                                  : null,
                            ),
                            Positioned(
                              right: -8,
                              bottom: -8,
                              child: IconButton.filled(
                                onPressed: _saving ? null : _pickAvatar,
                                style: IconButton.styleFrom(
                                  backgroundColor: _lightGreen,
                                  foregroundColor: Colors.white,
                                ),
                                icon: const Icon(Icons.photo_camera_rounded, size: 18),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(width: 16),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                name.isEmpty ? 'UMe user' : name,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 20,
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(
                                _username.isEmpty ? 'аккаунт UMe' : '@$_username',
                                style: TextStyle(
                                  color: Colors.white.withValues(alpha: 0.78),
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                  _SettingsSection(
                    title: 'Профиль',
                    children: [
                      _SettingsTextField(
                        controller: _nicknameController,
                        enabled: !_saving,
                        label: 'Никнейм',
                        icon: Icons.badge_outlined,
                      ),
                      const SizedBox(height: 10),
                      _SettingsTextField(
                        controller: _displayNameController,
                        enabled: !_saving,
                        label: 'Отображаемое имя',
                        icon: Icons.person_outline_rounded,
                      ),
                      const SizedBox(height: 12),
                      SizedBox(
                        width: double.infinity,
                        child: FilledButton.icon(
                          onPressed: _saving ? null : _saveProfile,
                          icon: const Icon(Icons.check_rounded),
                          label: const Text('СОХРАНИТЬ ПРОФИЛЬ'),
                        ),
                      ),
                    ],
                  ),
                  _SettingsSection(
                    title: 'Настройки приложения',
                    children: [
                      _SettingsChoiceTile(
                        icon: Icons.brightness_6_rounded,
                        title: 'Тема',
                        subtitle: _themeLabel(_theme),
                        child: SegmentedButton<String>(
                          selected: {_theme},
                          showSelectedIcon: false,
                          onSelectionChanged: _saving ? null : (value) => _saveTheme(value.first),
                          segments: const [
                            ButtonSegment(value: 'system', label: Text('Система')),
                            ButtonSegment(value: 'light', label: Text('Светлая')),
                            ButtonSegment(value: 'dark', label: Text('Тёмная')),
                          ],
                        ),
                      ),
                      const _SettingsDivider(),
                      _SettingsChoiceTile(
                        icon: Icons.notifications_active_outlined,
                        title: 'Уведомления',
                        subtitle: 'Управляются через разрешения браузера/Android',
                      ),
                      const _SettingsDivider(),
                      _SettingsChoiceTile(
                        icon: Icons.lock_outline_rounded,
                        title: 'Приватность',
                        subtitle: 'Личные чаты и сессия защищены токеном входа',
                      ),
                    ],
                  ),
                  _SettingsSection(
                    title: 'Внешний вид чатов',
                    children: [
                      _SettingsChoiceTile(
                        icon: Icons.palette_outlined,
                        title: 'Цвет акцента',
                        subtitle: _colorToHex(_accentColorValue(_accentColor)),
                        trailing: Container(
                          width: 28,
                          height: 28,
                          decoration: BoxDecoration(
                            color: _accentColorValue(_accentColor),
                            shape: BoxShape.circle,
                          ),
                        ),
                        onTap: _saving ? null : _openAccentColorPicker,
                      ),
                      const _SettingsDivider(),
                      _SettingsChoiceTile(
                        icon: Icons.chat_bubble_outline_rounded,
                        title: 'Пузыри сообщений',
                        subtitle: _bubbleLabel(_bubbleStyle),
                        child: SegmentedButton<String>(
                          selected: {_bubbleStyle},
                          showSelectedIcon: false,
                          onSelectionChanged: _saving
                              ? null
                              : (value) => _saveChatAppearance(bubbleStyle: value.first),
                          segments: const [
                            ButtonSegment(value: 'rounded', label: Text('Круглые')),
                            ButtonSegment(value: 'soft', label: Text('Мягкие')),
                            ButtonSegment(value: 'compact', label: Text('Компакт')),
                          ],
                        ),
                      ),
                      const _SettingsDivider(),
                      _SettingsChoiceTile(
                        icon: Icons.wallpaper_rounded,
                        title: 'Фон сообщений',
                        subtitle: _wallpaperLabel(_chatWallpaper),
                      ),
                      const SizedBox(height: 10),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          _WallpaperButton(
                            label: 'Обычный',
                            selected: _chatWallpaper == 'default',
                            onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'default'),
                          ),
                          _WallpaperButton(
                            label: 'Чистый',
                            selected: _chatWallpaper == 'clean',
                            onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'clean'),
                          ),
                          _WallpaperButton(
                            label: 'Градиент',
                            selected: _chatWallpaper == 'gradient',
                            onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'gradient'),
                          ),
                          _WallpaperButton(
                            label: 'Ночь',
                            selected: _chatWallpaper == 'night',
                            onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'night'),
                          ),
                          _WallpaperButton(
                            label: 'Мята',
                            selected: _chatWallpaper == 'mint',
                            onTap: _saving ? null : () => _saveChatAppearance(chatWallpaper: 'mint'),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      _WallpaperPreview(
                        value: _chatWallpaper,
                        accent: _accentColorValue(_accentColor),
                      ),
                      const SizedBox(height: 12),
                      OutlinedButton.icon(
                        onPressed: _saving ? null : _pickChatWallpaperImage,
                        icon: const Icon(Icons.image_outlined),
                        label: Text(_isCustomWallpaper ? 'Заменить свою картинку' : 'Поставить свою картинку'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
    );
  }

  String _themeLabel(String value) {
    switch (value) {
      case 'light':
        return 'Светлая';
      case 'dark':
        return 'Тёмная';
      default:
        return 'Как в системе';
    }
  }

  String _bubbleLabel(String value) {
    switch (value) {
      case 'soft':
        return 'Мягкие';
      case 'compact':
        return 'Компактные';
      default:
        return 'Круглые';
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
      default:
        return 'Обычный';
    }
  }
}

class _SettingsSection extends StatelessWidget {
  final String title;
  final List<Widget> children;

  const _SettingsSection({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 0),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: isDark ? const Color(0xFF1F2C34) : Colors.white,
          borderRadius: BorderRadius.circular(8),
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 14, 14, 14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                title,
                style: const TextStyle(
                  color: Color(0xFF075E54),
                  fontSize: 14,
                  fontWeight: FontWeight.w900,
                ),
              ),
              const SizedBox(height: 12),
              ...children,
            ],
          ),
        ),
      ),
    );
  }
}

class _SettingsTextField extends StatelessWidget {
  final TextEditingController controller;
  final bool enabled;
  final String label;
  final IconData icon;

  const _SettingsTextField({
    required this.controller,
    required this.enabled,
    required this.label,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      enabled: enabled,
      decoration: InputDecoration(
        labelText: label,
        prefixIcon: Icon(icon),
      ),
    );
  }
}

class _SettingsChoiceTile extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final Widget? child;
  final Widget? trailing;
  final VoidCallback? onTap;

  const _SettingsChoiceTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    this.child,
    this.trailing,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final body = Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, color: const Color(0xFF075E54)),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      title,
                      style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 15.5),
                    ),
                  ),
                  if (trailing != null) trailing!,
                ],
              ),
              const SizedBox(height: 3),
              Text(
                subtitle,
                style: const TextStyle(color: Color(0xFF667781), fontWeight: FontWeight.w500),
              ),
              if (child != null) ...[
                const SizedBox(height: 10),
                child!,
              ],
            ],
          ),
        ),
      ],
    );

    if (onTap == null) {
      return body;
    }

    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: body,
      ),
    );
  }
}

class _SettingsDivider extends StatelessWidget {
  const _SettingsDivider();

  @override
  Widget build(BuildContext context) {
    return const Padding(
      padding: EdgeInsets.symmetric(vertical: 12),
      child: Divider(height: 1, color: Color(0xFFE9E9E9)),
    );
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
            const Text('Палитра цвета', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
            const SizedBox(height: 14),
            Container(
              height: 92,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: _color,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Row(
                children: [
                  Icon(Icons.color_lens_outlined, color: textColor, size: 32),
                  const SizedBox(width: 12),
                  Text(
                    _hex(_color),
                    style: TextStyle(color: textColor, fontSize: 24, fontWeight: FontWeight.w900),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
            _ColorSlider(label: 'Оттенок', value: _hue, min: 0, max: 360, onChanged: (v) => setState(() => _hue = v)),
            _ColorSlider(label: 'Насыщенность', value: _saturation, min: 0, max: 1, onChanged: (v) => setState(() => _saturation = v)),
            _ColorSlider(label: 'Яркость', value: _value, min: 0.15, max: 1, onChanged: (v) => setState(() => _value = v)),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(child: OutlinedButton(onPressed: () => Navigator.of(context).pop(null), child: const Text('Отмена'))),
                const SizedBox(width: 12),
                Expanded(child: FilledButton(onPressed: () => Navigator.of(context).pop(_color), child: const Text('Применить'))),
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
            Expanded(child: Text(label, style: const TextStyle(fontWeight: FontWeight.w700))),
            Text(max == 360 ? value.round().toString() : '${(value * 100).round()}%'),
          ],
        ),
        Slider(value: value, min: min, max: max, onChanged: onChanged),
      ],
    );
  }
}

class _WallpaperButton extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback? onTap;

  const _WallpaperButton({required this.label, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return ChoiceChip(
      selected: selected,
      label: Text(label),
      onSelected: onTap == null ? null : (_) => onTap!(),
      selectedColor: const Color(0xFFD9FDD3),
    );
  }
}

class _WallpaperPreview extends StatelessWidget {
  final String value;
  final Color accent;

  const _WallpaperPreview({required this.value, required this.accent});

  bool get _isCustomImage {
    return value.startsWith('/uploads/') || value.startsWith('http://') || value.startsWith('https://');
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 116,
      decoration: _decoration(context),
      child: Stack(
        children: [
          Positioned(
            left: 14,
            top: 14,
            child: _Bubble(text: 'Привет!', color: Colors.white, textColor: Colors.black87),
          ),
          Positioned(
            right: 14,
            bottom: 14,
            child: _Bubble(text: 'Превью фона', color: const Color(0xFFD9FDD3), textColor: Colors.black87),
          ),
        ],
      ),
    );
  }

  BoxDecoration _decoration(BuildContext context) {
    if (_isCustomImage) {
      return BoxDecoration(
        borderRadius: BorderRadius.circular(8),
        image: DecorationImage(
          image: NetworkImage(ApiClient.absoluteUrl(value)),
          fit: BoxFit.cover,
          colorFilter: ColorFilter.mode(Colors.black.withValues(alpha: 0.22), BlendMode.darken),
        ),
      );
    }

    switch (value) {
      case 'clean':
        return BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(8));
      case 'gradient':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(8),
          gradient: LinearGradient(colors: [accent.withValues(alpha: 0.28), Colors.white]),
        );
      case 'night':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(8),
          gradient: const LinearGradient(colors: [Color(0xFF0B141A), Color(0xFF1F2C34)]),
        );
      case 'mint':
        return BoxDecoration(color: const Color(0xFFE8FFF5), borderRadius: BorderRadius.circular(8));
      case 'default':
      default:
        return BoxDecoration(color: const Color(0xFFECE5DD), borderRadius: BorderRadius.circular(8));
    }
  }
}

class _Bubble extends StatelessWidget {
  final String text;
  final Color color;
  final Color textColor;

  const _Bubble({required this.text, required this.color, required this.textColor});

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(maxWidth: 180),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(8)),
      child: Text(text, style: TextStyle(color: textColor, fontWeight: FontWeight.w600)),
    );
  }
}
