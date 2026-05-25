import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:mime/mime.dart';

class PickedInternalFile {
  final String name;
  final Uint8List bytes;
  final String mimeType;
  final bool sendAsFile;

  const PickedInternalFile({
    required this.name,
    required this.bytes,
    required this.mimeType,
    required this.sendAsFile,
  });
}

class InternalFileManager extends StatefulWidget {
  const InternalFileManager({super.key});

  @override
  State<InternalFileManager> createState() => _InternalFileManagerState();
}

class _InternalFileManagerState extends State<InternalFileManager>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController;

  PickedInternalFile? _selected;
  bool _sendAsFile = false;
  bool _picking = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _pick(FileType type) async {
    setState(() => _picking = true);

    try {
      final result = await FilePicker.pickFiles(
        type: type,
        allowMultiple: false,
        withData: true,
      );

      if (!mounted) return;

      if (result == null || result.files.isEmpty) return;

      final file = result.files.first;

      if (file.bytes == null) {
        _showError('Не удалось прочитать файл');
        return;
      }

      final mimeType = lookupMimeType(
            file.name,
            headerBytes: file.bytes,
          ) ??
          'application/octet-stream';

      setState(() {
        _selected = PickedInternalFile(
          name: file.name,
          bytes: file.bytes!,
          mimeType: mimeType,
          sendAsFile: _sendAsFile,
        );
      });
    } catch (e) {
      _showError(e.toString());
    } finally {
      if (mounted) {
        setState(() => _picking = false);
      }
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
      ),
    );
  }

  void _send() {
    final selected = _selected;

    if (selected == null) return;

    Navigator.of(context).pop(
      PickedInternalFile(
        name: selected.name,
        bytes: selected.bytes,
        mimeType: selected.mimeType,
        sendAsFile: _sendAsFile,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final selected = _selected;

    return SafeArea(
      child: Container(
        height: MediaQuery.of(context).size.height * 0.82,
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
        child: Column(
          children: [
            Container(
              width: 46,
              height: 5,
              margin: const EdgeInsets.only(bottom: 12),
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .outline
                    .withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(99),
              ),
            ),
            Row(
              children: [
                Icon(
                  Icons.folder_special_outlined,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Файловый менеджер',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.w800,
                        ),
                  ),
                ),
                IconButton(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.close),
                ),
              ],
            ),
            const SizedBox(height: 8),
            TabBar(
              controller: _tabController,
              tabs: const [
                Tab(
                  icon: Icon(Icons.image_outlined),
                  text: 'Фото',
                ),
                Tab(
                  icon: Icon(Icons.movie_outlined),
                  text: 'Видео',
                ),
                Tab(
                  icon: Icon(Icons.audiotrack_outlined),
                  text: 'Аудио',
                ),
                Tab(
                  icon: Icon(Icons.insert_drive_file_outlined),
                  text: 'Файлы',
                ),
              ],
            ),
            const SizedBox(height: 12),
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  _PickPanel(
                    icon: Icons.image_outlined,
                    title: 'Выберите изображение',
                    subtitle: 'PNG, JPG, JPEG, WEBP, GIF',
                    buttonText: 'Выбрать фото',
                    picking: _picking,
                    onPick: () => _pick(FileType.image),
                  ),
                  _PickPanel(
                    icon: Icons.movie_outlined,
                    title: 'Выберите видео',
                    subtitle: 'MP4, MKV, WEBM, MOV и другие',
                    buttonText: 'Выбрать видео',
                    picking: _picking,
                    onPick: () => _pick(FileType.video),
                  ),
                  _PickPanel(
                    icon: Icons.audiotrack_outlined,
                    title: 'Выберите аудио',
                    subtitle: 'MP3, WAV, OGG, M4A и другие',
                    buttonText: 'Выбрать аудио',
                    picking: _picking,
                    onPick: () => _pick(FileType.audio),
                  ),
                  _PickPanel(
                    icon: Icons.insert_drive_file_outlined,
                    title: 'Выберите любой файл',
                    subtitle: 'Документы, архивы и другие файлы',
                    buttonText: 'Выбрать файл',
                    picking: _picking,
                    onPick: () => _pick(FileType.any),
                  ),
                ],
              ),
            ),
            if (selected != null) ...[
              const SizedBox(height: 12),
              _SelectedFilePreview(
                file: selected,
              ),
              const SizedBox(height: 10),
              SwitchListTile(
                value: _sendAsFile,
                contentPadding: EdgeInsets.zero,
                title: const Text('Отправить как файл'),
                subtitle: const Text(
                  'Без медиа-превью, обычной карточкой файла',
                ),
                onChanged: (value) {
                  setState(() {
                    _sendAsFile = value;
                  });
                },
              ),
              const SizedBox(height: 8),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: _send,
                  icon: const Icon(Icons.send),
                  label: const Text('Отправить'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _PickPanel extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final String buttonText;
  final bool picking;
  final VoidCallback onPick;

  const _PickPanel({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.buttonText,
    required this.picking,
    required this.onPick,
  });

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(22),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircleAvatar(
                radius: 34,
                backgroundColor:
                    Theme.of(context).colorScheme.primary.withValues(alpha: 0.14),
                child: Icon(
                  icon,
                  size: 34,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
              const SizedBox(height: 14),
              Text(
                title,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
              ),
              const SizedBox(height: 6),
              Text(
                subtitle,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 18),
              FilledButton.icon(
                onPressed: picking ? null : onPick,
                icon: picking
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.folder_open),
                label: Text(buttonText),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SelectedFilePreview extends StatelessWidget {
  final PickedInternalFile file;

  const _SelectedFilePreview({
    required this.file,
  });

  bool get _isImage => file.mimeType.startsWith('image/');
  bool get _isVideo => file.mimeType.startsWith('video/');
  bool get _isAudio => file.mimeType.startsWith('audio/');

  String _sizeText(int bytes) {
    if (bytes < 1024) return '$bytes Б';
    if (bytes < 1024 * 1024) {
      return '${(bytes / 1024).toStringAsFixed(1)} КБ';
    }
    return '${(bytes / 1024 / 1024).toStringAsFixed(1)} МБ';
  }

  @override
  Widget build(BuildContext context) {
    final icon = _isImage
        ? Icons.image_outlined
        : _isVideo
            ? Icons.movie_outlined
            : _isAudio
                ? Icons.audiotrack_outlined
                : Icons.insert_drive_file_outlined;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context)
            .colorScheme
            .surfaceContainerHighest
            .withValues(alpha: 0.85),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: Theme.of(context).colorScheme.outlineVariant,
        ),
      ),
      child: Row(
        children: [
          if (_isImage)
            ClipRRect(
              borderRadius: BorderRadius.circular(14),
              child: Image.memory(
                file.bytes,
                width: 72,
                height: 72,
                fit: BoxFit.cover,
              ),
            )
          else
            CircleAvatar(
              radius: 34,
              backgroundColor:
                  Theme.of(context).colorScheme.primary.withValues(alpha: 0.14),
              child: Icon(
                icon,
                color: Theme.of(context).colorScheme.primary,
              ),
            ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  file.name,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '${file.mimeType} · ${_sizeText(file.bytes.length)}',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}