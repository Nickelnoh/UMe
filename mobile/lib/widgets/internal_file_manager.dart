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

  bool get isImage => mimeType.startsWith('image/');
  bool get isVideo => mimeType.startsWith('video/');
  bool get isAudio => mimeType.startsWith('audio/');
  bool get isMediaAlbumItem => !sendAsFile && (isImage || isVideo);
}

class InternalFileManager extends StatefulWidget {
  const InternalFileManager({super.key});

  @override
  State<InternalFileManager> createState() => _InternalFileManagerState();
}

class _InternalFileManagerState extends State<InternalFileManager>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController;

  final List<PickedInternalFile> _selected = [];
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
    if (_picking) return;

    setState(() => _picking = true);

    try {
      final result = await FilePicker.pickFiles(
        type: type,
        allowMultiple: true,
        withData: true,
      );

      if (!mounted) return;
      if (result == null || result.files.isEmpty) return;

      final files = <PickedInternalFile>[];

      for (final file in result.files) {
        final bytes = file.bytes;
        if (bytes == null) continue;

        final mimeType = lookupMimeType(
              file.name,
              headerBytes: bytes,
            ) ??
            'application/octet-stream';

        files.add(
          PickedInternalFile(
            name: file.name,
            bytes: bytes,
            mimeType: mimeType,
            sendAsFile: _sendAsFile,
          ),
        );
      }

      if (files.isEmpty) {
        _showError('Не удалось прочитать выбранные файлы');
        return;
      }

      setState(() {
        _selected.addAll(files);
      });
    } catch (e) {
      _showError(e.toString());
    } finally {
      if (mounted) {
        setState(() => _picking = false);
      }
    }
  }

  void _removeAt(int index) {
    setState(() => _selected.removeAt(index));
  }

  void _clear() {
    setState(() => _selected.clear());
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  void _send() {
    if (_selected.isEmpty) return;

    Navigator.of(context).pop(
      _selected
          .map(
            (file) => PickedInternalFile(
              name: file.name,
              bytes: file.bytes,
              mimeType: file.mimeType,
              sendAsFile: _sendAsFile,
            ),
          )
          .toList(growable: false),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final mediaCount = _selected.where((file) => file.isImage || file.isVideo).length;
    final albumHintVisible = mediaCount >= 2 && !_sendAsFile;

    return SafeArea(
      child: Container(
        height: MediaQuery.of(context).size.height * 0.86,
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
        child: Column(
          children: [
            Container(
              width: 46,
              height: 5,
              margin: const EdgeInsets.only(bottom: 12),
              decoration: BoxDecoration(
                color: theme.colorScheme.outline.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(99),
              ),
            ),
            Row(
              children: [
                CircleAvatar(
                  radius: 18,
                  backgroundColor: theme.colorScheme.primary.withValues(alpha: 0.14),
                  child: Icon(
                    Icons.folder_special_outlined,
                    color: theme.colorScheme.primary,
                    size: 20,
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Файлы',
                    style: theme.textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                ),
                if (_selected.isNotEmpty)
                  TextButton(
                    onPressed: _clear,
                    child: const Text('Очистить'),
                  ),
                IconButton(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.close),
                ),
              ],
            ),
            const SizedBox(height: 6),
            TabBar(
              controller: _tabController,
              tabs: const [
                Tab(icon: Icon(Icons.image_outlined), text: 'Фото'),
                Tab(icon: Icon(Icons.movie_outlined), text: 'Видео'),
                Tab(icon: Icon(Icons.audiotrack_outlined), text: 'Аудио'),
                Tab(icon: Icon(Icons.insert_drive_file_outlined), text: 'Файлы'),
              ],
            ),
            const SizedBox(height: 10),
            Expanded(
              child: Row(
                children: [
                  Expanded(
                    flex: 6,
                    child: TabBarView(
                      controller: _tabController,
                      children: [
                        _PickPanel(
                          icon: Icons.image_outlined,
                          title: 'Фото и картинки',
                          subtitle: 'Можно выбрать сразу несколько изображений',
                          buttonText: 'Выбрать фото',
                          picking: _picking,
                          onPick: () => _pick(FileType.image),
                        ),
                        _PickPanel(
                          icon: Icons.movie_outlined,
                          title: 'Видео',
                          subtitle: 'Можно выбрать сразу несколько роликов',
                          buttonText: 'Выбрать видео',
                          picking: _picking,
                          onPick: () => _pick(FileType.video),
                        ),
                        _PickPanel(
                          icon: Icons.audiotrack_outlined,
                          title: 'Аудио',
                          subtitle: 'Музыка, голосовые и другие аудиофайлы',
                          buttonText: 'Выбрать аудио',
                          picking: _picking,
                          onPick: () => _pick(FileType.audio),
                        ),
                        _PickPanel(
                          icon: Icons.insert_drive_file_outlined,
                          title: 'Файлы',
                          subtitle: 'Документы, архивы и любые вложения',
                          buttonText: 'Выбрать файлы',
                          picking: _picking,
                          onPick: () => _pick(FileType.any),
                        ),
                      ],
                    ),
                  ),
                  if (MediaQuery.of(context).size.width >= 720) ...[
                    const SizedBox(width: 12),
                    Expanded(
                      flex: 5,
                      child: _SelectedFilesPanel(
                        files: _selected,
                        onRemoveAt: _removeAt,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            if (MediaQuery.of(context).size.width < 720) ...[
              const SizedBox(height: 10),
              SizedBox(
                height: _selected.isEmpty ? 0 : 174,
                child: _SelectedFilesPanel(
                  files: _selected,
                  onRemoveAt: _removeAt,
                ),
              ),
            ],
            const SizedBox(height: 10),
            SwitchListTile(
              value: _sendAsFile,
              contentPadding: EdgeInsets.zero,
              title: const Text('Отправить как файлы'),
              subtitle: Text(
                albumHintVisible
                    ? 'Выключено: фото и видео будут собраны в альбом'
                    : 'Включено: вложения уйдут обычными файлами',
              ),
              onChanged: (value) => setState(() => _sendAsFile = value),
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _selected.isEmpty ? null : _send,
                icon: const Icon(Icons.send_rounded),
                label: Text(
                  _selected.isEmpty
                      ? 'Выберите вложения'
                      : 'Отправить: ${_selected.length}',
                ),
              ),
            ),
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
    final theme = Theme.of(context);

    return Center(
      child: Container(
        width: double.infinity,
        constraints: const BoxConstraints(maxWidth: 420),
        padding: const EdgeInsets.all(22),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.74),
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: theme.colorScheme.outlineVariant),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircleAvatar(
              radius: 36,
              backgroundColor: theme.colorScheme.primary.withValues(alpha: 0.14),
              child: Icon(icon, size: 36, color: theme.colorScheme.primary),
            ),
            const SizedBox(height: 14),
            Text(
              title,
              style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 6),
            Text(
              subtitle,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall,
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
                  : const Icon(Icons.add_photo_alternate_outlined),
              label: Text(buttonText),
            ),
          ],
        ),
      ),
    );
  }
}

class _SelectedFilesPanel extends StatelessWidget {
  final List<PickedInternalFile> files;
  final void Function(int index) onRemoveAt;

  const _SelectedFilesPanel({
    required this.files,
    required this.onRemoveAt,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    if (files.isEmpty) {
      return Container(
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.45),
          borderRadius: BorderRadius.circular(22),
          border: Border.all(color: theme.colorScheme.outlineVariant),
        ),
        child: Text(
          'Выбранные файлы появятся здесь',
          style: theme.textTheme.bodyMedium?.copyWith(
            color: theme.colorScheme.onSurface.withValues(alpha: 0.55),
            fontWeight: FontWeight.w700,
          ),
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: theme.colorScheme.outlineVariant),
      ),
      child: GridView.builder(
        itemCount: files.length,
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 3,
          mainAxisSpacing: 8,
          crossAxisSpacing: 8,
        ),
        itemBuilder: (context, index) {
          final file = files[index];
          return _SelectedFileTile(
            file: file,
            index: index,
            onRemove: () => onRemoveAt(index),
          );
        },
      ),
    );
  }
}

class _SelectedFileTile extends StatelessWidget {
  final PickedInternalFile file;
  final int index;
  final VoidCallback onRemove;

  const _SelectedFileTile({
    required this.file,
    required this.index,
    required this.onRemove,
  });

  String _sizeText(int bytes) {
    if (bytes < 1024) return '$bytes Б';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} КБ';
    return '${(bytes / 1024 / 1024).toStringAsFixed(1)} МБ';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final icon = file.isImage
        ? Icons.image_outlined
        : file.isVideo
            ? Icons.play_circle_outline_rounded
            : file.isAudio
                ? Icons.audiotrack_rounded
                : Icons.insert_drive_file_outlined;

    return ClipRRect(
      borderRadius: BorderRadius.circular(18),
      child: Stack(
        children: [
          Positioned.fill(
            child: file.isImage
                ? Image.memory(file.bytes, fit: BoxFit.cover)
                : Container(
                    color: theme.colorScheme.primary.withValues(alpha: 0.12),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(icon, color: theme.colorScheme.primary, size: 30),
                        const SizedBox(height: 6),
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 6),
                          child: Text(
                            file.name,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: theme.colorScheme.onSurface,
                              fontSize: 10,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                        ),
                        Text(
                          _sizeText(file.bytes.length),
                          style: TextStyle(
                            color: theme.colorScheme.onSurface.withValues(alpha: 0.58),
                            fontSize: 9,
                          ),
                        ),
                      ],
                    ),
                  ),
          ),
          Positioned(
            left: 6,
            top: 6,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.58),
                borderRadius: BorderRadius.circular(999),
              ),
              child: Text(
                '${index + 1}',
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 11,
                  fontWeight: FontWeight.w900,
                ),
              ),
            ),
          ),
          if (file.isVideo)
            const Center(
              child: Icon(
                Icons.play_circle_fill_rounded,
                color: Colors.white,
                size: 34,
              ),
            ),
          Positioned(
            right: 4,
            top: 4,
            child: InkWell(
              onTap: onRemove,
              borderRadius: BorderRadius.circular(999),
              child: Container(
                width: 28,
                height: 28,
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.58),
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.close, color: Colors.white, size: 18),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
