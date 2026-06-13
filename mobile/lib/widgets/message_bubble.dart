import 'dart:async';
import 'dart:typed_data';
import 'package:audioplayers/audioplayers.dart';
import 'package:flutter/material.dart';
import 'package:video_player/video_player.dart';

import '../core/api_client.dart';
import '../core/attachment_download_store.dart';
import '../core/attachment_file_saver.dart';

class VoicePlaybackQueue {
  static List<String> _urls = const [];
  static final Map<String, _VoicePlaybackEntry> _entries = {};

  static void setUrls(List<String> urls) {
    final unique = <String>[];

    for (final url in urls) {
      if (url.trim().isEmpty) continue;
      if (unique.contains(url)) continue;
      unique.add(url);
    }

    _urls = unique;
  }

  static void register(
    String url, {
    required Future<void> Function() play,
    required Future<void> Function() stop,
  }) {
    _entries[url] = _VoicePlaybackEntry(
      play: play,
      stop: stop,
    );
  }

  static void unregister(String url) {
    _entries.remove(url);
  }

  static Future<void> play(String url) async {
    final target = _entries[url];

    if (target == null) return;

    for (final entry in _entries.entries) {
      if (entry.key == url) continue;
      await entry.value.stop();
    }

    await target.play();
  }

  static Future<void> pause(String url) async {
    final target = _entries[url];
    if (target == null) return;

    await target.stop();
  }

  static Future<void> playNextAfter(String currentUrl) async {
    final currentIndex = _urls.indexOf(currentUrl);

    if (currentIndex == -1) return;

    for (int i = currentIndex + 1; i < _urls.length; i++) {
      final nextUrl = _urls[i];

      if (_entries.containsKey(nextUrl)) {
        await play(nextUrl);
        return;
      }
    }
  }
}

class _VoicePlaybackEntry {
  final Future<void> Function() play;
  final Future<void> Function() stop;

  const _VoicePlaybackEntry({
    required this.play,
    required this.stop,
  });
}

class MessageBubble extends StatelessWidget {
  final String? text;
  final Map<String, dynamic>? attachment;
  final String? senderName;
  final bool isMine;
  final String? editedAt;
  final String? deliveryStatus;
  final String? forwardedFromName;
  final bool pinned;
  final List<dynamic> reactions;
  final Color? accentColor;
  final String bubbleStyle;
  final VoidCallback? onLongPress;
  final VoidCallback? onTap;

  const MessageBubble({
    super.key,
    required this.text,
    required this.attachment,
    this.senderName,
    required this.isMine,
    this.editedAt,
    this.deliveryStatus,
    this.forwardedFromName,
    this.pinned = false,
    this.reactions = const [],
    this.accentColor,
    this.bubbleStyle = 'rounded',
    this.onLongPress,
    this.onTap,
  });

  Future<void> _openAttachment(BuildContext context) async {
    final rawUrl = attachment?['url']?.toString();
    if (rawUrl == null || rawUrl.isEmpty) return;

    final url = ApiClient.absoluteUrl(rawUrl);
    final kind = attachment?['kind']?.toString() ?? 'other';
    final name = attachment?['original_name']?.toString() ?? 'file';
    final cached = AttachmentDownloadStore.get(url);

    if (kind == 'image') {
      await showDialog(
        context: context,
        builder: (_) => _ImageViewerDialog(
          url: url,
          title: name,
          bytes: cached?.bytes,
        ),
      );
      return;
    }

    if (kind == 'video') {
      await showDialog(
        context: context,
        builder: (_) => _VideoViewerDialog(
          url: url,
          title: name,
          downloaded: cached,
        ),
      );
      return;
    }

    if (cached != null) {
      await showDialog(
        context: context,
        builder: (_) => _DownloadedFileDialog(entry: cached),
      );
      return;
    }

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Сначала скачайте файл внутри UMe'),
        ),
      );
    }
  }

  IconData _statusIcon() {
    switch (deliveryStatus) {
      case 'read':
      case 'delivered':
        return Icons.done_all_rounded;
      case 'sent':
      default:
        return Icons.check_rounded;
    }
  }

  String _statusTooltip() {
    switch (deliveryStatus) {
      case 'read':
        return 'Прочитано';
      case 'delivered':
        return 'Доставлено';
      case 'sent':
      default:
        return 'Отправлено';
    }
  }

  @override
  Widget build(BuildContext context) {
    final accent = accentColor ?? Theme.of(context).colorScheme.primary;

    final color = isMine
        ? const Color(0xFFDCF8C6)
        : Colors.white;

    final textColor = const Color(0xFF111111);

    final radius = switch (bubbleStyle) {
      'compact' => 10.0,
      'soft' => 16.0,
      _ => 22.0,
    };

    final verticalPadding = bubbleStyle == 'compact' ? 7.0 : 10.0;
    final horizontalPadding = bubbleStyle == 'compact' ? 10.0 : 12.0;

    final edited = editedAt != null && editedAt!.trim().isNotEmpty;

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(radius),
          onTap: onTap,
          onLongPress: onLongPress,
          child: Container(
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.76,
            ),
            margin: EdgeInsets.only(
              left: isMine ? 72 : 8,
              right: isMine ? 8 : 72,
              top: 4,
              bottom: 4,
            ),
            child: Column(
              crossAxisAlignment:
                  isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                AnimatedContainer(
                  duration: const Duration(milliseconds: 180),
                  padding: EdgeInsets.symmetric(
                    horizontal: horizontalPadding,
                    vertical: verticalPadding,
                  ),
                  decoration: BoxDecoration(
                    color: color,
                    borderRadius: BorderRadius.only(
                      topLeft: Radius.circular(radius),
                      topRight: Radius.circular(radius),
                      bottomLeft: Radius.circular(isMine ? radius : 5),
                      bottomRight: Radius.circular(isMine ? 5 : radius),
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.08),
                        blurRadius: 10,
                        offset: const Offset(0, 3),
                      ),
                    ],
                  ),
                  child: Column(
                    crossAxisAlignment: isMine
                        ? CrossAxisAlignment.end
                        : CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (!isMine &&
                          senderName != null &&
                          senderName!.isNotEmpty) ...[
                        Text(
                          senderName!,
                          style:
                              Theme.of(context).textTheme.labelSmall?.copyWith(
                                    color: textColor.withValues(alpha: 0.75),
                                    fontWeight: FontWeight.w600,
                                  ),
                        ),
                        const SizedBox(height: 4),
                      ],
                      if (forwardedFromName != null &&
                          forwardedFromName!.trim().isNotEmpty) ...[
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.shortcut_rounded,
                              size: 14,
                              color: textColor.withValues(alpha: 0.62),
                            ),
                            const SizedBox(width: 4),
                            ConstrainedBox(
                              constraints: BoxConstraints(
                                maxWidth: MediaQuery.of(context).size.width * 0.52,
                              ),
                              child: Text(
                                'Переслано от ${forwardedFromName!}',
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                      color: textColor.withValues(alpha: 0.66),
                                      fontWeight: FontWeight.w700,
                                    ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 5),
                      ],
                      if (pinned) ...[
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.push_pin_rounded,
                              size: 14,
                              color: textColor.withValues(alpha: 0.62),
                            ),
                            const SizedBox(width: 4),
                            Text(
                              'Закреплено',
                              style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                    color: textColor.withValues(alpha: 0.66),
                                    fontWeight: FontWeight.w700,
                                  ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 5),
                      ],
                      if (attachment != null) ...[
                        _AttachmentPreview(
                          attachment: attachment!,
                          textColor: textColor,
                          onOpen: () => _openAttachment(context),
                        ),
                        if (text != null && text!.trim().isNotEmpty)
                          const SizedBox(height: 8),
                      ],
                      if (text != null && text!.trim().isNotEmpty)
                        Text(
                          text!,
                          style:
                              Theme.of(context).textTheme.bodyMedium?.copyWith(
                                    color: textColor,
                                  ),
                        ),
                      if (edited) ...[
                        const SizedBox(height: 4),
                        Text(
                          'изменено',
                          style:
                              Theme.of(context).textTheme.labelSmall?.copyWith(
                                    color: textColor.withValues(alpha: 0.6),
                                  ),
                        ),
                      ],
                      if (isMine) ...[
                        const SizedBox(height: 4),
                        Tooltip(
                          message: _statusTooltip(),
                          child: Icon(
                            _statusIcon(),
                            size: 16,
                            color: deliveryStatus == 'read'
                                ? accent
                                : textColor.withValues(alpha: 0.58),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                if (reactions.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: _ReactionBar(
                      reactions: reactions,
                      accentColor: accent,
                      isMine: isMine,
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ReactionBar extends StatelessWidget {
  final List<dynamic> reactions;
  final Color accentColor;
  final bool isMine;

  const _ReactionBar({
    required this.reactions,
    required this.accentColor,
    required this.isMine,
  });

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 4,
      runSpacing: 4,
      alignment: isMine ? WrapAlignment.end : WrapAlignment.start,
      children: reactions.map((raw) {
        final reaction = raw is Map
            ? Map<String, dynamic>.from(raw)
            : <String, dynamic>{};

        final mine = reaction['is_mine'] == true;
        final type = reaction['reaction_type']?.toString();
        final emoji = reaction['emoji']?.toString();

        final attachment = reaction['attachment'] is Map
            ? Map<String, dynamic>.from(reaction['attachment'] as Map)
            : null;

        Widget child;

        if (type == 'image' && attachment != null) {
          final url = ApiClient.absoluteUrl(attachment['url']?.toString());

          child = ClipRRect(
            borderRadius: BorderRadius.circular(12),
            child: Image.network(
              url,
              width: 30,
              height: 30,
              fit: BoxFit.cover,
              errorBuilder: (_, __, ___) {
                return const SizedBox(
                  width: 30,
                  height: 30,
                  child: Icon(
                    Icons.broken_image_outlined,
                    size: 18,
                  ),
                );
              },
            ),
          );
        } else {
          child = Text(
            emoji == null || emoji.isEmpty ? '👍' : emoji,
            style: const TextStyle(fontSize: 18),
          );
        }

        return Tooltip(
          message: reaction['user_name']?.toString() ?? 'Реакция',
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 160),
            padding: EdgeInsets.symmetric(
              horizontal: type == 'image' ? 3 : 8,
              vertical: type == 'image' ? 3 : 4,
            ),
            decoration: BoxDecoration(
              color: mine
                  ? accentColor.withValues(alpha: 0.20)
                  : Theme.of(context).colorScheme.surface.withValues(
                        alpha: 0.92,
                      ),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: mine
                    ? accentColor.withValues(alpha: 0.75)
                    : Theme.of(context).colorScheme.outlineVariant,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.08),
                  blurRadius: 8,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: child,
          ),
        );
      }).toList(),
    );
  }
}


Future<void> _exportDownloadedAttachment(
  BuildContext context,
  DownloadedAttachment entry,
  String successMessage,
) async {
  Navigator.of(context).pop();

  final saved = await saveAttachmentBytes(
    bytes: entry.bytes,
    name: entry.name,
    mimeType: entry.mimeType,
  );

  if (!context.mounted) return;

  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(
        saved
            ? successMessage
            : 'На этой платформе доступно только внутреннее скачивание UMe',
      ),
    ),
  );
}

Future<void> _showAttachmentSaveSheet(
  BuildContext context,
  DownloadedAttachment entry, {
  required String kind,
}) async {
  final normalizedKind = kind.toLowerCase();
  final isMedia = normalizedKind == 'image' || normalizedKind == 'video';
  final isAudio = normalizedKind == 'audio';

  await showModalBottomSheet<void>(
    context: context,
    showDragHandle: true,
    builder: (sheetContext) {
      return SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 4, 20, 12),
              child: Row(
                children: [
                  const Icon(Icons.download_done_rounded),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          entry.name,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontWeight: FontWeight.w800),
                        ),
                        Text(
                          'Скачано в UMe · ${AttachmentDownloadStore.formatSize(entry.sizeBytes)}',
                          style: Theme.of(sheetContext).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            if (isMedia)
              ListTile(
                leading: const Icon(Icons.photo_library_outlined),
                title: const Text('Сохранить в галерею'),
                subtitle: const Text('В браузере файл сохранится через системную загрузку'),
                onTap: () => _exportDownloadedAttachment(
                  sheetContext,
                  entry,
                  'Файл передан на сохранение в галерею',
                ),
              ),
            if (isAudio)
              ListTile(
                leading: const Icon(Icons.music_note_rounded),
                title: const Text('Сохранить в музыку'),
                subtitle: const Text('В браузере файл сохранится через системную загрузку'),
                onTap: () => _exportDownloadedAttachment(
                  sheetContext,
                  entry,
                  'Аудио передано на сохранение в музыку',
                ),
              ),
            ListTile(
              leading: const Icon(Icons.folder_copy_outlined),
              title: const Text('Сохранить в загрузки'),
              subtitle: const Text('Скачать файл из внутреннего кеша UMe на устройство'),
              onTap: () => _exportDownloadedAttachment(
                sheetContext,
                entry,
                'Файл передан в загрузки',
              ),
            ),
          ],
        ),
      );
    },
  );
}

bool _looksLikeVoiceMessage(String name, String mimeType) {
  final lowerName = name.toLowerCase().trim();
  final lowerMime = mimeType.toLowerCase().trim();

  return lowerName.startsWith('voice_') ||
      lowerName.startsWith('voice-') ||
      lowerName.contains('/voice') ||
      (lowerName.endsWith('.wav') && lowerMime.contains('audio'));
}

class _AttachmentPreview extends StatefulWidget {
  final Map<String, dynamic> attachment;
  final Color textColor;
  final VoidCallback onOpen;

  const _AttachmentPreview({
    required this.attachment,
    required this.textColor,
    required this.onOpen,
  });

  @override
  State<_AttachmentPreview> createState() => _AttachmentPreviewState();
}

class _AttachmentPreviewState extends State<_AttachmentPreview> {
  String get _kind => widget.attachment['kind']?.toString() ?? 'other';
  String get _url => ApiClient.absoluteUrl(widget.attachment['url']?.toString());
  String get _name => widget.attachment['original_name']?.toString() ?? 'file';
  String get _mimeType => widget.attachment['mime_type']?.toString() ?? 'application/octet-stream';

  bool get _hasDownloadableUrl => _url.trim().isNotEmpty;

  void _refresh() {
    if (!mounted) return;
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final cached = AttachmentDownloadStore.get(_url);

    if (_kind == 'image') {
      return InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: widget.onOpen,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(14),
          child: Stack(
            alignment: Alignment.bottomLeft,
            children: [
              if (cached != null)
                Image.memory(
                  cached.bytes,
                  width: 260,
                  height: 220,
                  fit: BoxFit.cover,
                )
              else
                Image.network(
                  _url,
                  width: 260,
                  height: 220,
                  fit: BoxFit.cover,
                  errorBuilder: (_, __, ___) {
                    return _FileCard(
                      icon: Icons.broken_image,
                      name: _name,
                      label: 'Не удалось загрузить изображение',
                      textColor: widget.textColor,
                      url: _url,
                      mimeType: _mimeType,
                      kind: 'image',
                      onOpen: widget.onOpen,
                    );
                  },
                ),
              Container(
                width: 260,
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 6,
                ),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.bottomCenter,
                    end: Alignment.topCenter,
                    colors: [
                      Colors.black.withValues(alpha: 0.55),
                      Colors.transparent,
                    ],
                  ),
                ),
                child: Text(
                  cached == null ? _name : 'Скачано в UMe · $_name',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                  ),
                ),
              ),
              if (_hasDownloadableUrl)
                Positioned(
                  top: 8,
                  right: 8,
                  child: _AttachmentDownloadButton(
                    url: _url,
                    name: _name,
                    mimeType: _mimeType,
                    kind: 'image',
                    compact: true,
                    textColor: Colors.white,
                    backgroundColor: Colors.black.withValues(alpha: 0.55),
                    onDownloaded: _refresh,
                    onOpenDownloaded: () {
                      final entry = AttachmentDownloadStore.get(_url);
                      if (entry == null) return;
                      _showAttachmentSaveSheet(context, entry, kind: 'image');
                    },
                  ),
                ),
            ],
          ),
        ),
      );
    }

    if (_kind == 'video') {
      return _FileCard(
        icon: Icons.play_circle_outline,
        name: _name,
        label: cached == null ? 'Видео' : 'Видео · скачано в UMe',
        textColor: widget.textColor,
        url: _url,
        mimeType: _mimeType,
        kind: 'video',
        onOpen: widget.onOpen,
      );
    }

    if (_kind == 'audio') {
      return _AudioPlayerCard(
        url: _url,
        name: _name,
        textColor: widget.textColor,
        sizeBytes: int.tryParse(
          widget.attachment['size_bytes']?.toString() ??
              widget.attachment['file_size']?.toString() ??
              widget.attachment['size']?.toString() ??
              '',
        ),
        mimeType: _mimeType,
      );
    }

    if (_kind == 'document') {
      return _FileCard(
        icon: Icons.description_outlined,
        name: _name,
        label: cached == null ? 'Документ' : 'Документ · скачано в UMe',
        textColor: widget.textColor,
        url: _url,
        mimeType: _mimeType,
        kind: _kind,
        onOpen: widget.onOpen,
      );
    }

    if (_kind == 'file') {
      return _FileCard(
        icon: Icons.insert_drive_file_outlined,
        name: _name,
        label: cached == null ? 'Файл' : 'Файл · скачано в UMe',
        textColor: widget.textColor,
        url: _url,
        mimeType: _mimeType,
        kind: _kind,
        onOpen: widget.onOpen,
      );
    }

    return _FileCard(
      icon: Icons.attach_file,
      name: _name,
      label: cached == null ? 'Файл' : 'Файл · скачано в UMe',
      textColor: widget.textColor,
      url: _url,
      mimeType: _mimeType,
      onOpen: widget.onOpen,
    );
  }
}


class _AudioPlayerCard extends StatefulWidget {
  final String url;
  final String name;
  final Color textColor;
  final int? sizeBytes;
  final String mimeType;

  const _AudioPlayerCard({
    required this.url,
    required this.name,
    required this.textColor,
    required this.sizeBytes,
    required this.mimeType,
  });

  @override
  State<_AudioPlayerCard> createState() => _AudioPlayerCardState();
}

class _AudioPlayerCardState extends State<_AudioPlayerCard> {
  final AudioPlayer _player = AudioPlayer();

  bool _isPlaying = false;
  bool _sourceReady = false;
  Duration _position = Duration.zero;
  Duration _duration = Duration.zero;

  @override
  void initState() {
    super.initState();

    VoicePlaybackQueue.register(
      widget.url,
      play: _playFromQueue,
      stop: _stopFromQueue,
    );

    final estimated = _estimateWavDuration();
    if (estimated != null) {
      _duration = estimated;
    }

    unawaited(_prepareSource());

    _player.onDurationChanged.listen((duration) {
      if (!mounted) return;
      setState(() => _duration = duration);
    });

    _player.onPositionChanged.listen((position) {
      if (!mounted) return;
      setState(() => _position = position);
    });

    _player.onPlayerComplete.listen((_) {
      if (!mounted) return;

      setState(() {
        _isPlaying = false;
        _position = Duration.zero;
      });

      unawaited(VoicePlaybackQueue.playNextAfter(widget.url));
    });
  }

  Duration? _estimateWavDuration() {
    final size = widget.sizeBytes;

    if (size == null || size <= 44) return null;
    if (!widget.name.toLowerCase().endsWith('.wav')) return null;

    const sampleRate = 16000;
    const channels = 1;
    const bytesPerSample = 2;
    const byteRate = sampleRate * channels * bytesPerSample;

    final audioBytes = size - 44;
    final milliseconds = (audioBytes / byteRate * 1000).round();

    if (milliseconds <= 0) return null;

    return Duration(milliseconds: milliseconds);
  }

  Future<void> _prepareSource() async {
    if (_sourceReady) return;

    try {
      final cached = AttachmentDownloadStore.get(widget.url);
      if (cached != null) {
        await _player.setSource(BytesSource(cached.bytes));
      } else {
        await _player.setSource(UrlSource(widget.url));
      }
      final duration = await _player.getDuration();

      if (!mounted) return;

      setState(() {
        _sourceReady = true;
        if (duration != null) {
          _duration = duration;
        }
      });
    } catch (_) {
      // Duration can still arrive through onDurationChanged after playback starts.
    }
  }

  Future<void> _toggle() async {
    if (_isPlaying) {
      await VoicePlaybackQueue.pause(widget.url);
      return;
    }

    await VoicePlaybackQueue.play(widget.url);
  }

  Future<void> _playFromQueue() async {
    await _prepareSource();

    try {
      await _player.resume();
    } catch (_) {
      final cached = AttachmentDownloadStore.get(widget.url);
      if (cached != null) {
        await _player.play(BytesSource(cached.bytes));
      } else {
        await _player.play(UrlSource(widget.url));
      }
    }

    final duration = await _player.getDuration();

    if (!mounted) return;

    setState(() {
      _isPlaying = true;
      if (duration != null) {
        _duration = duration;
      }
    });
  }

  Future<void> _stopFromQueue() async {
    try {
      await _player.pause();
    } catch (_) {}

    if (!mounted) return;

    setState(() => _isPlaying = false);
  }

  Future<void> _seek(double value) async {
    final next = Duration(milliseconds: value.toInt());
    await _player.seek(next);
  }

  String _format(Duration value) {
    final minutes = value.inMinutes.remainder(60).toString().padLeft(2, '0');
    final seconds = value.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
  }

  @override
  void dispose() {
    VoicePlaybackQueue.unregister(widget.url);
    _player.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final max = _duration.inMilliseconds <= 0
        ? 1.0
        : _duration.inMilliseconds.toDouble();

    final current = _position.inMilliseconds.clamp(0, max.toInt()).toDouble();

    return Container(
      constraints: const BoxConstraints(
        minWidth: 250,
        maxWidth: 300,
      ),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: widget.textColor.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: widget.textColor.withValues(alpha: 0.12),
        ),
      ),
      child: Row(
        children: [
          IconButton.filledTonal(
            onPressed: _toggle,
            icon: Icon(
              _isPlaying ? Icons.pause : Icons.play_arrow,
            ),
          ),
          const SizedBox(width: 8),
          if (!_looksLikeVoiceMessage(widget.name, widget.mimeType)) ...[
            _AttachmentDownloadButton(
              url: widget.url,
              name: widget.name,
              mimeType: widget.mimeType,
              kind: 'audio',
              compact: true,
              textColor: widget.textColor,
              onDownloaded: () {
                if (!mounted) return;
                setState(() {
                  _sourceReady = false;
                });
                unawaited(_prepareSource());
              },
              onOpenDownloaded: () {
                final entry = AttachmentDownloadStore.get(widget.url);
                if (entry == null) return;
                _showAttachmentSaveSheet(context, entry, kind: 'audio');
              },
            ),
            const SizedBox(width: 8),
          ],
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Slider(
                  value: current,
                  min: 0,
                  max: max,
                  onChanged: _seek,
                ),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      _format(_position),
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                            color: widget.textColor.withValues(alpha: 0.7),
                          ),
                    ),
                    Text(
                      _format(_duration),
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                            color: widget.textColor.withValues(alpha: 0.7),
                          ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _FileCard extends StatefulWidget {
  final IconData icon;
  final String name;
  final String? label;
  final Color textColor;
  final String url;
  final String mimeType;
  final String kind;
  final VoidCallback onOpen;

  const _FileCard({
    required this.icon,
    required this.name,
    this.label,
    required this.textColor,
    required this.url,
    required this.mimeType,
    this.kind = 'other',
    required this.onOpen,
  });

  @override
  State<_FileCard> createState() => _FileCardState();
}

class _FileCardState extends State<_FileCard> {
  void _refresh() {
    if (!mounted) return;
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final cached = AttachmentDownloadStore.get(widget.url);

    return InkWell(
      borderRadius: BorderRadius.circular(14),
      onTap: cached == null ? null : widget.onOpen,
      child: Container(
        constraints: const BoxConstraints(
          minWidth: 220,
          maxWidth: 300,
        ),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: widget.textColor.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: widget.textColor.withValues(alpha: 0.12),
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircleAvatar(
              backgroundColor: widget.textColor.withValues(alpha: 0.12),
              child: Icon(
                cached == null ? widget.icon : Icons.download_done_rounded,
                color: widget.textColor,
              ),
            ),
            const SizedBox(width: 10),
            Flexible(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (widget.label != null)
                    Text(
                      widget.label!,
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                            color: widget.textColor.withValues(alpha: 0.75),
                          ),
                    ),
                  Text(
                    widget.name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: widget.textColor,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    cached == null
                        ? 'Скачать внутри UMe'
                        : 'Скачано: ${AttachmentDownloadStore.formatSize(cached.sizeBytes)}',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                          color: widget.textColor.withValues(alpha: 0.65),
                        ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            _AttachmentDownloadButton(
              url: widget.url,
              name: widget.name,
              mimeType: widget.mimeType,
              kind: widget.kind,
              textColor: widget.textColor,
              onDownloaded: _refresh,
              onOpenDownloaded: () {
                final entry = AttachmentDownloadStore.get(widget.url);
                if (entry == null) return;
                _showAttachmentSaveSheet(context, entry, kind: widget.kind);
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _AttachmentDownloadButton extends StatefulWidget {
  final String url;
  final String name;
  final String mimeType;
  final String kind;
  final Color textColor;
  final Color? backgroundColor;
  final bool compact;
  final VoidCallback onDownloaded;
  final VoidCallback onOpenDownloaded;

  const _AttachmentDownloadButton({
    required this.url,
    required this.name,
    required this.mimeType,
    this.kind = 'other',
    required this.textColor,
    this.backgroundColor,
    this.compact = false,
    required this.onDownloaded,
    required this.onOpenDownloaded,
  });

  @override
  State<_AttachmentDownloadButton> createState() => _AttachmentDownloadButtonState();
}

class _AttachmentDownloadButtonState extends State<_AttachmentDownloadButton> {
  bool _downloading = false;
  double? _progress;
  String? _label;

  bool get _downloaded => AttachmentDownloadStore.isDownloaded(widget.url);

  Future<void> _download() async {
    if (_downloading) return;

    if (_downloaded) {
      widget.onOpenDownloaded();
      return;
    }

    setState(() {
      _downloading = true;
      _progress = null;
      _label = '0%';
    });

    try {
      final entry = await AttachmentDownloadStore.download(
        url: widget.url,
        name: widget.name,
        mimeType: widget.mimeType,
        onProgress: (progress) {
          if (!mounted) return;

          final value = progress.value;

          setState(() {
            _progress = value;
            _label = value == null
                ? AttachmentDownloadStore.formatSize(progress.downloadedBytes)
                : '${(value * 100).clamp(0, 100).round()}%';
          });
        },
      );

      if (!mounted) return;

      setState(() {
        _downloading = false;
        _progress = 1;
        _label = AttachmentDownloadStore.formatSize(entry.sizeBytes);
      });

      widget.onDownloaded();
    } catch (_) {
      if (!mounted) return;

      setState(() {
        _downloading = false;
        _progress = null;
        _label = null;
      });

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Не удалось скачать файл внутри UMe'),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = widget.compact ? 38.0 : 42.0;
    final iconSize = widget.compact ? 19.0 : 21.0;
    final background = widget.backgroundColor ?? const Color(0xFF1F2C34);
    final foreground = widget.backgroundColor == null ? Colors.white : widget.textColor;

    return Tooltip(
      message: _downloaded ? 'Открыть скачанное' : 'Скачать внутри UMe',
      child: InkResponse(
        radius: size / 2,
        onTap: _download,
        child: SizedBox(
          width: size,
          height: size,
          child: Stack(
            alignment: Alignment.center,
            children: [
              DecoratedBox(
                decoration: BoxDecoration(
                  color: background,
                  shape: BoxShape.circle,
                ),
                child: SizedBox(width: size, height: size),
              ),
              if (_downloading)
                SizedBox(
                  width: size - 8,
                  height: size - 8,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.4,
                    value: _progress,
                    color: foreground,
                  ),
                ),
              Icon(
                _downloaded ? Icons.download_done_rounded : Icons.arrow_downward_rounded,
                color: foreground,
                size: iconSize,
              ),
              if (_downloading && !widget.compact && _label != null)
                Positioned(
                  bottom: 0,
                  child: Text(
                    _label!,
                    style: TextStyle(
                      color: foreground,
                      fontSize: 8,
                      fontWeight: FontWeight.w800,
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

class _DownloadedFileDialog extends StatelessWidget {
  final DownloadedAttachment entry;

  const _DownloadedFileDialog({required this.entry});

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Файл скачан внутри UMe'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            entry.name,
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 8),
          Text('Размер: ${AttachmentDownloadStore.formatSize(entry.sizeBytes)}'),
          Text('Тип: ${entry.mimeType}'),
          const SizedBox(height: 12),
          const Text(
            'Файл сохранён во внутреннем кеше мессенджера и открывается из UMe без повторной загрузки.',
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Готово'),
        ),
      ],
    );
  }
}


class _ImageViewerDialog extends StatelessWidget {
  final String url;
  final String title;
  final Uint8List? bytes;

  const _ImageViewerDialog({
    required this.url,
    required this.title,
    this.bytes,
  });

  @override
  Widget build(BuildContext context) {
    return Dialog.fullscreen(
      backgroundColor: Colors.black,
      child: Stack(
        children: [
          Center(
            child: InteractiveViewer(
              minScale: 0.8,
              maxScale: 4,
              child: bytes == null
                  ? Image.network(
                      url,
                      fit: BoxFit.contain,
                    )
                  : Image.memory(
                      bytes!,
                      fit: BoxFit.contain,
                    ),
            ),
          ),
          Positioned(
            top: 12,
            left: 8,
            right: 8,
            child: SafeArea(
              child: Row(
                children: [
                  IconButton.filledTonal(
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: Colors.white),
                    ),
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

class _VideoViewerDialog extends StatefulWidget {
  final String url;
  final String title;
  final DownloadedAttachment? downloaded;

  const _VideoViewerDialog({
    required this.url,
    required this.title,
    this.downloaded,
  });

  @override
  State<_VideoViewerDialog> createState() => _VideoViewerDialogState();
}

class _VideoViewerDialogState extends State<_VideoViewerDialog> {
  late final VideoPlayerController _controller;

  bool _ready = false;
  bool _showControls = true;

  @override
  void initState() {
    super.initState();

    _controller = VideoPlayerController.networkUrl(Uri.parse(widget.url));

    _controller.initialize().then((_) {
      if (!mounted) return;

      setState(() => _ready = true);
      _controller.play();
    });

    _controller.addListener(() {
      if (!mounted) return;
      setState(() {});
    });
  }

  Future<void> _togglePlay() async {
    if (_controller.value.isPlaying) {
      await _controller.pause();
    } else {
      await _controller.play();
    }

    if (!mounted) return;
    setState(() {});
  }

  String _format(Duration value) {
    final minutes = value.inMinutes.remainder(60).toString().padLeft(2, '0');
    final seconds = value.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final position = _ready ? _controller.value.position : Duration.zero;
    final duration = _ready ? _controller.value.duration : Duration.zero;

    final max = duration.inMilliseconds <= 0
        ? 1.0
        : duration.inMilliseconds.toDouble();

    final current = position.inMilliseconds.clamp(0, max.toInt()).toDouble();

    return Dialog.fullscreen(
      backgroundColor: Colors.black,
      child: Stack(
        children: [
          Center(
            child: _ready
                ? GestureDetector(
                    onTap: () {
                      setState(() => _showControls = !_showControls);
                    },
                    child: AspectRatio(
                      aspectRatio: _controller.value.aspectRatio,
                      child: VideoPlayer(_controller),
                    ),
                  )
                : const CircularProgressIndicator(),
          ),
          if (_showControls)
            Positioned(
              top: 12,
              left: 8,
              right: 8,
              child: SafeArea(
                child: Row(
                  children: [
                    IconButton.filledTonal(
                      onPressed: () => Navigator.of(context).pop(),
                      icon: const Icon(Icons.close),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            widget.title,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(color: Colors.white),
                          ),
                          if (widget.downloaded != null)
                            Text(
                              'Скачано в UMe · ${AttachmentDownloadStore.formatSize(widget.downloaded!.sizeBytes)}',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                color: Colors.white.withValues(alpha: 0.72),
                                fontSize: 12,
                              ),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          if (_showControls)
            Positioned(
              left: 12,
              right: 12,
              bottom: 16,
              child: SafeArea(
                child: Container(
                  padding: const EdgeInsets.fromLTRB(8, 6, 8, 6),
                  decoration: BoxDecoration(
                    color: Colors.black.withValues(alpha: 0.55),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    children: [
                      IconButton(
                        color: Colors.white,
                        onPressed: _ready ? _togglePlay : null,
                        icon: Icon(
                          _controller.value.isPlaying
                              ? Icons.pause
                              : Icons.play_arrow,
                        ),
                      ),
                      Text(
                        _format(position),
                        style: const TextStyle(color: Colors.white),
                      ),
                      Expanded(
                        child: Slider(
                          value: current,
                          min: 0,
                          max: max,
                          onChanged: !_ready
                              ? null
                              : (value) {
                                  _controller.seekTo(
                                    Duration(milliseconds: value.toInt()),
                                  );
                                },
                        ),
                      ),
                      Text(
                        _format(duration),
                        style: const TextStyle(color: Colors.white),
                      ),
                    ],
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}