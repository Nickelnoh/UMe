import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

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
  String _accentColor = 'blue';
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
    setState(() => _loading = true);

    try {
      final me = await ApiClient.get('/me');

      if (!mounted) return;

      setState(() {
        _username = me['username']?.toString() ?? '';
        _nickname = me['nickname']?.toString() ?? '';
        _displayName = me['display_name']?.toString() ?? '';
        _avatarUrl = me['avatar_url']?.toString();

        _theme = me['theme']?.toString() ?? 'system';
        _accentColor = me['accent_color']?.toString() ?? 'blue';
        _chatWallpaper = me['chat_wallpaper']?.toString() ?? 'default';
        _bubbleStyle = me['bubble_style']?.toString() ?? 'rounded';

        _nicknameController.text = _nickname;
        _displayNameController.text = _displayName;
      });
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
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

      TopNotification.success(
        context,
        message: 'Профиль сохранён',
      );

      await _loadMe();
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
  }

  Future<void> _saveTheme(String value) async {
    setState(() {
      _theme = value;
      _saving = true;
    });

    try {
      await ApiClient.post(
        '/settings/theme',
        {'theme': value},
      );

      if (!mounted) return;

      TopNotification.success(
        context,
        message: 'Тема сохранена',
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
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

      TopNotification.success(
        context,
        message: 'Вид чата сохранён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
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

      setState(() {
        _avatarUrl = response['url']?.toString();
      });

      TopNotification.success(
        context,
        message: 'Аватар обновлён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
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

      setState(() {
        _chatWallpaper = wallpaperUrl;
      });

      TopNotification.success(
        context,
        message: 'Фон чата обновлён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
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

    if (text.contains('Nickname already exists')) {
      return 'Никнейм уже занят';
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

  Color _accentColorValue(String value) {
    final parsed = _parseAccentColor(value);

    if (parsed != null) return parsed;

    switch (value) {
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
      builder: (context) {
        return _AccentColorPickerSheet(
          initialColor: initialColor,
        );
      },
    );

    if (selected == null) return;

    await _saveChatAppearance(
      accentColor: _colorToHex(selected),
    );
  }

  bool get _isCustomWallpaper {
    return _chatWallpaper.startsWith('/uploads/') ||
        _chatWallpaper.startsWith('http://') ||
        _chatWallpaper.startsWith('https://');
  }

  @override
  Widget build(BuildContext context) {
    final avatar = _avatarUrl == null || _avatarUrl!.isEmpty
        ? null
        : ApiClient.absoluteUrl(_avatarUrl);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Настройки'),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : SafeArea(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
                children: [
                  _SectionCard(
                    title: 'Профиль',
                    subtitle: _username.isEmpty ? null : '@$_username',
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Center(
                          child: Stack(
                            clipBehavior: Clip.none,
                            children: [
                              CircleAvatar(
                                radius: 48,
                                backgroundImage: avatar == null
                                    ? null
                                    : NetworkImage(avatar),
                                child: avatar == null
                                    ? Text(
                                        (_displayName.isNotEmpty
                                                ? _displayName
                                                : _username)
                                            .characters
                                            .first
                                            .toUpperCase(),
                                        style: const TextStyle(fontSize: 30),
                                      )
                                    : null,
                              ),
                              Positioned(
                                right: -6,
                                bottom: -6,
                                child: IconButton.filled(
                                  onPressed: _saving ? null : _pickAvatar,
                                  icon: const Icon(Icons.photo_camera_outlined),
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(height: 20),
                        TextField(
                          controller: _nicknameController,
                          enabled: !_saving,
                          decoration: const InputDecoration(
                            labelText: 'Никнейм',
                            prefixIcon: Icon(Icons.badge_outlined),
                            border: OutlineInputBorder(),
                          ),
                        ),
                        const SizedBox(height: 12),
                        TextField(
                          controller: _displayNameController,
                          enabled: !_saving,
                          decoration: const InputDecoration(
                            labelText: 'Отображаемое имя',
                            prefixIcon: Icon(Icons.person_outline),
                            border: OutlineInputBorder(),
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
                  ),
                  const SizedBox(height: 12),
                  _SectionCard(
                    title: 'Тема приложения',
                    subtitle: 'Сохраняется на сервере',
                    child: SegmentedButton<String>(
                      selected: {_theme},
                      onSelectionChanged: _saving
                          ? null
                          : (value) => _saveTheme(value.first),
                      segments: const [
                        ButtonSegment(
                          value: 'system',
                          icon: Icon(Icons.settings_suggest_outlined),
                          label: Text('Система'),
                        ),
                        ButtonSegment(
                          value: 'light',
                          icon: Icon(Icons.light_mode_outlined),
                          label: Text('Светлая'),
                        ),
                        ButtonSegment(
                          value: 'dark',
                          icon: Icon(Icons.dark_mode_outlined),
                          label: Text('Тёмная'),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                  _SectionCard(
                    title: 'Кастомизация чата',
                    subtitle: 'Цвета, пузыри и фон сообщений',
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Text(
                          'Акцентный цвет',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                        const SizedBox(height: 10),
                        _AccentPreviewCard(
                          color: _accentColorValue(_accentColor),
                          hex: _colorToHex(_accentColorValue(_accentColor)),
                          onTap: _saving ? null : _openAccentColorPicker,
                        ),
                        const SizedBox(height: 22),
                        Text(
                          'Стиль сообщений',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                        const SizedBox(height: 10),
                        SegmentedButton<String>(
                          selected: {_bubbleStyle},
                          onSelectionChanged: _saving
                              ? null
                              : (value) => _saveChatAppearance(
                                    bubbleStyle: value.first,
                                  ),
                          segments: const [
                            ButtonSegment(
                              value: 'rounded',
                              label: Text('Круглый'),
                            ),
                            ButtonSegment(
                              value: 'soft',
                              label: Text('Мягкий'),
                            ),
                            ButtonSegment(
                              value: 'compact',
                              label: Text('Компакт'),
                            ),
                          ],
                        ),
                        const SizedBox(height: 22),
                        Text(
                          'Фон чата',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                        const SizedBox(height: 10),
                        _WallpaperPreview(
                          value: _chatWallpaper,
                          accent: _accentColorValue(_accentColor),
                        ),
                        const SizedBox(height: 10),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: [
                            _WallpaperButton(
                              label: 'Обычный',
                              selected: _chatWallpaper == 'default',
                              onTap: _saving
                                  ? null
                                  : () => _saveChatAppearance(
                                        chatWallpaper: 'default',
                                      ),
                            ),
                            _WallpaperButton(
                              label: 'Чистый',
                              selected: _chatWallpaper == 'clean',
                              onTap: _saving
                                  ? null
                                  : () => _saveChatAppearance(
                                        chatWallpaper: 'clean',
                                      ),
                            ),
                            _WallpaperButton(
                              label: 'Градиент',
                              selected: _chatWallpaper == 'gradient',
                              onTap: _saving
                                  ? null
                                  : () => _saveChatAppearance(
                                        chatWallpaper: 'gradient',
                                      ),
                            ),
                            _WallpaperButton(
                              label: 'Ночь',
                              selected: _chatWallpaper == 'night',
                              onTap: _saving
                                  ? null
                                  : () => _saveChatAppearance(
                                        chatWallpaper: 'night',
                                      ),
                            ),
                            _WallpaperButton(
                              label: 'Мята',
                              selected: _chatWallpaper == 'mint',
                              onTap: _saving
                                  ? null
                                  : () => _saveChatAppearance(
                                        chatWallpaper: 'mint',
                                      ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        OutlinedButton.icon(
                          onPressed: _saving ? null : _pickChatWallpaperImage,
                          icon: const Icon(Icons.image_outlined),
                          label: Text(
                            _isCustomWallpaper
                                ? 'Заменить свою картинку'
                                : 'Поставить свою картинку',
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

class _SectionCard extends StatelessWidget {
  final String title;
  final String? subtitle;
  final Widget child;

  const _SectionCard({
    required this.title,
    required this.child,
    this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(
            alpha: 0.55,
          ),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(22),
        side: BorderSide(
          color: Theme.of(context).colorScheme.outlineVariant.withValues(
                alpha: 0.6,
              ),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              title,
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
            ),
            if (subtitle != null) ...[
              const SizedBox(height: 2),
              Text(
                subtitle!,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
            const SizedBox(height: 16),
            child,
          ],
        ),
      ),
    );
  }
}

class _AccentPreviewCard extends StatelessWidget {
  final Color color;
  final String hex;
  final VoidCallback? onTap;

  const _AccentPreviewCard({
    required this.color,
    required this.hex,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final textColor = color.computeLuminance() > 0.55
        ? Colors.black
        : Colors.white;

    return InkWell(
      borderRadius: BorderRadius.circular(20),
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(20),
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              color.withValues(alpha: 0.95),
              color.withValues(alpha: 0.55),
            ],
          ),
          boxShadow: [
            BoxShadow(
              color: color.withValues(alpha: 0.28),
              blurRadius: 22,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Row(
          children: [
            Container(
              width: 52,
              height: 52,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
                border: Border.all(
                  color: Colors.white.withValues(alpha: 0.75),
                  width: 3,
                ),
              ),
              child: Icon(
                Icons.palette_outlined,
                color: textColor,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Текущий цвет',
                    style: TextStyle(
                      color: textColor.withValues(alpha: 0.82),
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    hex,
                    style: TextStyle(
                      color: textColor,
                      fontSize: 20,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 0.8,
                    ),
                  ),
                ],
              ),
            ),
            Icon(
              Icons.tune,
              color: textColor,
            ),
          ],
        ),
      ),
    );
  }
}

class _AccentColorPickerSheet extends StatefulWidget {
  final Color initialColor;

  const _AccentColorPickerSheet({
    required this.initialColor,
  });

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

  Color get _color {
    return HSVColor.fromAHSV(1, _hue, _saturation, _value).toColor();
  }

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
              'Палитра цвета',
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
            ),
            const SizedBox(height: 14),
            AnimatedContainer(
              duration: const Duration(milliseconds: 140),
              height: 118,
              padding: const EdgeInsets.all(18),
              decoration: BoxDecoration(
                color: _color,
                borderRadius: BorderRadius.circular(24),
                boxShadow: [
                  BoxShadow(
                    color: _color.withValues(alpha: 0.35),
                    blurRadius: 26,
                    offset: const Offset(0, 12),
                  ),
                ],
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.color_lens_outlined,
                    color: textColor,
                    size: 34,
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          'Будущий акцент',
                          style: TextStyle(
                            color: textColor.withValues(alpha: 0.82),
                            fontWeight: FontWeight.w600,
                          ),
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
              child: Text(
                label,
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
            Text(
              max == 360 ? value.round().toString() : '${(value * 100).round()}%',
              style: Theme.of(context).textTheme.labelMedium,
            ),
          ],
        ),
        Slider(
          value: value,
          min: min,
          max: max,
          onChanged: onChanged,
        ),
      ],
    );
  }
}

class _WallpaperButton extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback? onTap;

  const _WallpaperButton({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return ChoiceChip(
      selected: selected,
      label: Text(label),
      onSelected: onTap == null ? null : (_) => onTap!(),
    );
  }
}

class _WallpaperPreview extends StatelessWidget {
  final String value;
  final Color accent;

  const _WallpaperPreview({
    required this.value,
    required this.accent,
  });

  bool get _isCustomImage {
    return value.startsWith('/uploads/') ||
        value.startsWith('http://') ||
        value.startsWith('https://');
  }

  @override
  Widget build(BuildContext context) {
    final decoration = _decoration(context);

    return AnimatedContainer(
      duration: const Duration(milliseconds: 220),
      height: 132,
      decoration: decoration,
      child: Stack(
        children: [
          Positioned(
            left: 14,
            top: 16,
            child: _Bubble(
              text: 'Привет!',
              color: Theme.of(context).colorScheme.surface.withValues(
                    alpha: 0.88,
                  ),
              alignRight: false,
            ),
          ),
          Positioned(
            right: 14,
            bottom: 16,
            child: _Bubble(
              text: 'Это превью фона',
              color: accent,
              alignRight: true,
            ),
          ),
          if (_isCustomImage)
            Positioned(
              left: 12,
              bottom: 12,
              child: DecoratedBox(
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.45),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  child: Text(
                    'Своя картинка',
                    style: TextStyle(color: Colors.white, fontSize: 12),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  BoxDecoration _decoration(BuildContext context) {
    if (_isCustomImage) {
      return BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        image: DecorationImage(
          image: NetworkImage(ApiClient.absoluteUrl(value)),
          fit: BoxFit.cover,
          colorFilter: ColorFilter.mode(
            Colors.black.withValues(alpha: 0.25),
            BlendMode.darken,
          ),
        ),
      );
    }

    switch (value) {
      case 'clean':
        return BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          borderRadius: BorderRadius.circular(22),
        );
      case 'gradient':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(22),
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              accent.withValues(alpha: 0.35),
              Theme.of(context).colorScheme.surface,
              accent.withValues(alpha: 0.15),
            ],
          ),
        );
      case 'night':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(22),
          gradient: const LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xFF0F172A),
              Color(0xFF1E1B4B),
              Color(0xFF111827),
            ],
          ),
        );
      case 'mint':
        return BoxDecoration(
          borderRadius: BorderRadius.circular(22),
          gradient: const LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              Color(0xFFE8FFF5),
              Color(0xFFF6FFFB),
              Color(0xFFEFFFF9),
            ],
          ),
        );
      case 'default':
      default:
        return BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(22),
        );
    }
  }
}

class _Bubble extends StatelessWidget {
  final String text;
  final Color color;
  final bool alignRight;

  const _Bubble({
    required this.text,
    required this.color,
    required this.alignRight,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(maxWidth: 190),
      padding: const EdgeInsets.symmetric(horizontal: 13, vertical: 9),
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(18),
      ),
      child: Text(
        text,
        style: TextStyle(
          color: alignRight ? Colors.white : null,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}
