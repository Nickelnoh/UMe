import 'dart:async';
import 'package:audioplayers/audioplayers.dart';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:video_player/video_player.dart';

import '../core/api_client.dart';

class MessageBubble extends StatelessWidget {
  final String? text;
  final Map<String, dynamic>? attachment;
  final String? senderName;
  final bool isMine;
  final String? editedAt;
  final List<dynamic> reactions;
  final Color? accentColor;
  final String bubbleStyle;
  final VoidCallback? onLongPress;

  const MessageBubble({
    super.key,
    required this.text,
    required this.attachment,
    this.senderName,
    required this.isMine,
    this.editedAt,
    this.reactions = const [],
    this.accentColor,
    this.bubbleStyle = 'rounded',
    this.onLongPress,
  });

  Future<void> _openAttachment(BuildContext context) async {
    final rawUrl = attachment?['url']?.toString();
    if (rawUrl == null || rawUrl.isEmpty) return;

    final url = ApiClient.absoluteUrl(rawUrl);
    final kind = attachment?['kind']?.toString() ?? 'other';
    final name = attachment?['original_name']?.toString() ?? 'file';

    if (kind == 'image') {
      await showDialog(
        context: context,
        builder: (_) => _ImageViewerDialog(
          url: url,
          title: name,
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
        ),
      );
      return;
    }

    final uri = Uri.parse(url);

    final opened = await launchUrl(
      uri,
      mode: LaunchMode.externalApplication,
    );

    if (!opened && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Не удалось открыть файл'),
        ),
      );
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

class _AttachmentPreview extends StatelessWidget {
  final Map<String, dynamic> attachment;
  final Color textColor;
  final VoidCallback onOpen;

  const _AttachmentPreview({
    required this.attachment,
    required this.textColor,
    required this.onOpen,
  });

  @override
  Widget build(BuildContext context) {
    final kind = attachment['kind']?.toString() ?? 'other';
    final url = ApiClient.absoluteUrl(attachment['url']?.toString());
    final name = attachment['original_name']?.toString() ?? 'file';

    if (kind == 'image') {
      return InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onOpen,
        child: ClipRRect(
          borderRadius: BorderRadius.circular(14),
          child: Stack(
            alignment: Alignment.bottomLeft,
            children: [
              Image.network(
                url,
                width: 260,
                height: 220,
                fit: BoxFit.cover,
                errorBuilder: (_, __, ___) {
                  return _FileCard(
                    icon: Icons.broken_image,
                    name: name,
                    label: 'Не удалось загрузить изображение',
                    textColor: textColor,
                    onTap: onOpen,
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
                  name,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    }

    if (kind == 'video') {
      return _FileCard(
        icon: Icons.play_circle_outline,
        name: name,
        label: 'Видео',
        textColor: textColor,
        onTap: onOpen,
      );
    }

    if (kind == 'audio') {
      return _AudioPlayerCard(
        url: url,
        name: name,
        textColor: textColor,
        sizeBytes: int.tryParse(
          attachment['size_bytes']?.toString() ??
              attachment['file_size']?.toString() ??
              attachment['size']?.toString() ??
              '',
        ),
      );
    }

    if (kind == 'document') {
      return _FileCard(
        icon: Icons.description_outlined,
        name: name,
        label: 'Документ',
        textColor: textColor,
        onTap: onOpen,
      );
    }

    if (kind == 'file') {
      return _FileCard(
        icon: Icons.insert_drive_file_outlined,
        name: name,
        label: 'Файл',
        textColor: textColor,
        onTap: onOpen,
      );
    }

    return _FileCard(
      icon: Icons.attach_file,
      name: name,
      label: 'Файл',
      textColor: textColor,
      onTap: onOpen,
    );
  }
}

class _AudioPlayerCard extends StatefulWidget {
  final String url;
  final String name;
  final Color textColor;
  final int? sizeBytes;

  const _AudioPlayerCard({
    required this.url,
    required this.name,
    required this.textColor,
    required this.sizeBytes,
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
      await _player.setSource(UrlSource(widget.url));
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
      await _player.pause();
      setState(() => _isPlaying = false);
      return;
    }

    await _prepareSource();

    try {
      await _player.resume();
    } catch (_) {
      await _player.play(UrlSource(widget.url));
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

class _FileCard extends StatelessWidget {
  final IconData icon;
  final String name;
  final String? label;
  final Color textColor;
  final VoidCallback onTap;

  const _FileCard({
    required this.icon,
    required this.name,
    this.label,
    required this.textColor,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(14),
      onTap: onTap,
      child: Container(
        constraints: const BoxConstraints(
          minWidth: 220,
          maxWidth: 280,
        ),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: textColor.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: textColor.withValues(alpha: 0.12),
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircleAvatar(
              backgroundColor: textColor.withValues(alpha: 0.12),
              child: Icon(
                icon,
                color: textColor,
              ),
            ),
            const SizedBox(width: 10),
            Flexible(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (label != null)
                    Text(
                      label!,
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                            color: textColor.withValues(alpha: 0.75),
                          ),
                    ),
                  Text(
                    name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: textColor,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    'Нажмите, чтобы открыть',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                          color: textColor.withValues(alpha: 0.65),
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

class _ImageViewerDialog extends StatelessWidget {
  final String url;
  final String title;

  const _ImageViewerDialog({
    required this.url,
    required this.title,
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
              child: Image.network(
                url,
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

  const _VideoViewerDialog({
    required this.url,
    required this.title,
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
                      child: Text(
                        widget.title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(color: Colors.white),
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