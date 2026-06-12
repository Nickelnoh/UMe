import 'dart:async';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:record/record.dart';

import '../../core/api_client.dart';
import '../../core/websocket_service.dart';
import '../../widgets/message_bubble.dart';
import '../../widgets/top_notification.dart';
import '../../widgets/internal_file_manager.dart';
// ignore: unused_element
enum _AttachmentMode {
  media,
  file,
}

class ChatScreen extends StatefulWidget {
  final String chatId;
  final String title;
  final bool isGroup;

  const ChatScreen({
    super.key,
    required this.chatId,
    required this.title,
    this.isGroup = false,
  });

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();
  final _ws = WebSocketService();
  final _recorder = AudioRecorder();

  StreamSubscription<Map<String, dynamic>>? _wsSubscription;
  StreamSubscription<Uint8List>? _recordSubscription;

  bool _loading = true;
  bool _sending = false;
  bool _recording = false;
  bool _recordLocked = false;
  bool _hasTextInput = false;

  DateTime? _recordingStartedAt;
  Timer? _recordingTicker;
  Duration _recordingElapsed = Duration.zero;
  double _voiceLockProgress = 0.0;

  String? _myUserId;
  late String _title;
  String _accentColor = 'blue';
  String _chatWallpaper = 'default';
  String _bubbleStyle = 'rounded';

  final List<int> _recordedPcmBytes = [];
  List<dynamic> _messages = [];

  static const int _voiceSampleRate = 16000;
  static const int _voiceChannels = 1;

  @override
  void initState() {
    super.initState();
    _title = widget.title;
    _messageController.addListener(_handleTextInputChanged);
    _init();
  }

  Future<void> _init() async {
    await _loadMe();
    await _loadMessages();
    await _connectWebSocket();
  }

  void _handleTextInputChanged() {
    final hasText = _messageController.text.trim().isNotEmpty;

    if (_hasTextInput == hasText) return;
    if (!mounted) return;

    setState(() {
      _hasTextInput = hasText;
    });
  }

  void _startRecordingTicker() {
    _recordingTicker?.cancel();

    _recordingTicker = Timer.periodic(
      const Duration(milliseconds: 250),
      (_) {
        final started = _recordingStartedAt;

        if (!mounted || started == null || !_recording) return;

        setState(() {
          _recordingElapsed = DateTime.now().difference(started);
        });
      },
    );
  }

  void _stopRecordingTicker() {
    _recordingTicker?.cancel();
    _recordingTicker = null;
  }

  Future<void> _loadMe() async {
    try {
      final me = await ApiClient.get('/me');

      if (!mounted) return;

      setState(() {
        _myUserId = me['id']?.toString();
        _accentColor = me['accent_color']?.toString() ?? 'blue';
        _chatWallpaper = me['chat_wallpaper']?.toString() ?? 'default';
        _bubbleStyle = me['bubble_style']?.toString() ?? 'rounded';
      });
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _connectWebSocket() async {
    try {
      await _ws.connect();

      if (!mounted) return;

      _wsSubscription = _ws.events.listen((event) {
        if (!mounted) return;

        final type = event['type']?.toString();
        final chatId = event['chat_id']?.toString();

        if (chatId != widget.chatId) return;

        if (type == 'chat.updated') {
          final nextTitle = event['title']?.toString();

          if (nextTitle != null && nextTitle.trim().isNotEmpty) {
            setState(() => _title = nextTitle);
          }

          return;
        }

        if (type == 'chat.members.updated') {
          return;
        }

        if (type == 'message.created') {
          final rawMessage = event['message'];

          if (rawMessage is! Map) return;

          final message = Map<String, dynamic>.from(rawMessage);
          final exists = _messages.any((item) => item['id'] == message['id']);

          if (exists) return;

          final senderId = message['sender_user_id']?.toString();

          setState(() {
            _messages.add({
              ...message,
              'is_mine': senderId == _myUserId,
            });
          });

          if (senderId != _myUserId) {
            final messageText = message['text']?.toString().trim();

            TopNotification.message(
              context,
              title: 'Новое сообщение',
              message: messageText != null && messageText.isNotEmpty
                  ? messageText
                  : 'Новое вложение',
            );
          }

          _scrollToBottom();
          return;
        }

        if (type == 'message.updated') {
          final rawMessage = event['message'];

          if (rawMessage is! Map) return;

          final updated = Map<String, dynamic>.from(rawMessage);

          setState(() {
            final index = _messages.indexWhere(
              (item) => item['id'] == updated['id'],
            );

            if (index != -1) {
              final old = Map<String, dynamic>.from(_messages[index] as Map);

              _messages[index] = {
                ...old,
                ...updated,
                'is_mine': old['is_mine'] == true ||
                    updated['sender_user_id']?.toString() == _myUserId,
              };
            }
          });

          return;
        }

        if (type == 'message.deleted') {
          final messageId = event['message_id']?.toString();

          if (messageId == null) return;

          setState(() {
            _messages.removeWhere(
              (item) => item['id']?.toString() == messageId,
            );
          });

          return;
        }

        if (type == 'reaction.updated') {
          final messageId = event['message_id']?.toString();
          final rawReaction = event['reaction'];

          if (messageId == null || rawReaction is! Map) return;

          final reaction = Map<String, dynamic>.from(rawReaction);
          final reactionUserId = reaction['user_id']?.toString();

          setState(() {
            final index = _messages.indexWhere(
              (item) => item['id']?.toString() == messageId,
            );

            if (index == -1) return;

            final message = Map<String, dynamic>.from(_messages[index] as Map);
            final reactions = (message['reactions'] is List)
                ? List<dynamic>.from(message['reactions'] as List)
                : <dynamic>[];

            reactions.removeWhere(
              (item) => item is Map && item['user_id']?.toString() == reactionUserId,
            );

            reactions.add({
              ...reaction,
              'is_mine': reactionUserId == _myUserId,
            });

            message['reactions'] = reactions;
            _messages[index] = message;
          });

          return;
        }

        if (type == 'reaction.deleted') {
          final messageId = event['message_id']?.toString();
          final reactionUserId = event['user_id']?.toString();

          if (messageId == null || reactionUserId == null) return;

          setState(() {
            final index = _messages.indexWhere(
              (item) => item['id']?.toString() == messageId,
            );

            if (index == -1) return;

            final message = Map<String, dynamic>.from(_messages[index] as Map);
            final reactions = (message['reactions'] is List)
                ? List<dynamic>.from(message['reactions'] as List)
                : <dynamic>[];

            reactions.removeWhere(
              (item) => item is Map && item['user_id']?.toString() == reactionUserId,
            );

            message['reactions'] = reactions;
            _messages[index] = message;
          });

          return;
        }
      });
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _loadMessages() async {
    setState(() => _loading = true);

    try {
      final result = await ApiClient.get(
        '/chats/${widget.chatId}/messages',
      );

      if (!mounted) return;

      setState(() {
        _messages = (result as List<dynamic>).map((item) {
          final map = Map<String, dynamic>.from(item as Map);
          map['is_mine'] = map['sender_user_id']?.toString() == _myUserId;
          return map;
        }).toList();
      });

      _scrollToBottom();
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _sendTextMessage() async {
    final text = _messageController.text.trim();

    if (text.isEmpty) return;

    await _sendMessage(text: text);
  }


  Future<void> _openInternalFileManager() async {
    final picked = await showModalBottomSheet<PickedInternalFile>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      showDragHandle: false,
      builder: (_) => const InternalFileManager(),
    );

    if (picked == null) return;

    try {
      if (!mounted) return;

      setState(() => _sending = true);

      final uploaded = await ApiClient.uploadBytes(
        path: '/attachments/upload',
        bytes: picked.bytes,
        filename: picked.name,
        fields: {
          'send_as_file': picked.sendAsFile ? 'true' : 'false',
        },
      );

      final attachmentId = uploaded['id']?.toString();

      if (attachmentId == null || attachmentId.isEmpty) {
        throw Exception('Сервер не вернул attachment id');
      }

      await _sendMessage(
        attachmentId: attachmentId,
        clearInput: false,
        manageSendingState: false,
      );

      if (!mounted) return;

      TopNotification.success(
        context,
        message: 'Файл отправлен',
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _sending = false);
      }
    }
  }

// ignore: unused_element
  Future<void> _pickAndSendFiles() async {
    try {
      final result = await FilePicker.pickFiles(
        withData: true,
        allowMultiple: true,
        type: FileType.any,
      );

      if (result == null || result.files.isEmpty) return;

      final files = result.files.where((file) => file.bytes != null).toList();

      if (files.isEmpty) {
        _showError('Не удалось прочитать выбранные файлы');
        return;
      }

      if (!mounted) return;

      final options = await _showMultiAttachmentSheet(files);

      if (options == null) return;

      if (!mounted) return;

      setState(() => _sending = true);

      for (int i = 0; i < files.length; i++) {
        final file = files[i];
        final bytes = file.bytes;

        if (bytes == null) continue;

        final uploaded = await ApiClient.uploadBytes(
          path: '/attachments/upload',
          bytes: bytes,
          filename: file.name,
          fields: {
            'send_as_file':
                options.mode == _AttachmentMode.file ? 'true' : 'false',
          },
        );

        final caption = i == 0 ? options.caption.trim() : '';

        await _sendMessage(
          text: caption.isEmpty ? null : caption,
          attachmentId: uploaded['id']?.toString(),
          clearInput: false,
          manageSendingState: false,
        );
      }

      _messageController.clear();

      if (mounted) {
        TopNotification.success(
          context,
          message: files.length == 1
              ? 'Файл отправлен'
              : 'Файлы отправлены: ${files.length}',
        );
      }
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _sending = false);
      }
    }
  }

  Future<void> _startVoiceRecording({bool locked = false}) async {
    if (_recording || _sending) return;

    try {
      final hasPermission = await _recorder.hasPermission();

      if (!hasPermission) {
        _showError('Нет доступа к микрофону');
        return;
      }

      _recordedPcmBytes.clear();

      final stream = await _recorder.startStream(
        const RecordConfig(
          encoder: AudioEncoder.pcm16bits,
          sampleRate: _voiceSampleRate,
          numChannels: _voiceChannels,
        ),
      );

      _recordSubscription = stream.listen((chunk) {
        _recordedPcmBytes.addAll(chunk);
      });

      if (!mounted) return;

      setState(() {
        _recording = true;
        _recordLocked = locked;
        _recordingStartedAt = DateTime.now();
        _recordingElapsed = Duration.zero;
        _voiceLockProgress = locked ? 1.0 : 0.0;
      });

      _startRecordingTicker();
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  void _lockVoiceRecording() {
    if (!_recording || _recordLocked) return;

    setState(() {
      _recordLocked = true;
      _voiceLockProgress = 1.0;
    });
  }

  Future<void> _handleMicLongPressStart(LongPressStartDetails details) async {
    if (_hasTextInput || _sending) return;
    await _startVoiceRecording();
  }

  void _handleMicLongPressMoveUpdate(LongPressMoveUpdateDetails details) {
    if (!_recording || _recordLocked) return;

    final progress = (-details.offsetFromOrigin.dy / 90).clamp(0.0, 1.0);

    if (progress != _voiceLockProgress && mounted) {
      setState(() {
        _voiceLockProgress = progress;
      });
    }

    if (progress >= 0.88) {
      _lockVoiceRecording();
    }
  }

  Future<void> _handleMicLongPressEnd(LongPressEndDetails details) async {
    if (!_recording || _recordLocked) return;
    await _stopVoiceRecordingAndSend();
  }

  void _handleMicTap() {
    if (_sending) return;

    if (_recording && _recordLocked) {
      _stopVoiceRecordingAndSend();
    }
  }

  Future<void> _stopVoiceRecordingAndSend() async {
    if (!_recording) return;

    try {
      _stopRecordingTicker();

      setState(() {
        _recording = false;
        _recordLocked = false;
        _recordingStartedAt = null;
        _recordingElapsed = Duration.zero;
        _voiceLockProgress = 0.0;
        _sending = true;
      });

      await _recordSubscription?.cancel();
      _recordSubscription = null;

      await _recorder.stop();

      if (_recordedPcmBytes.isEmpty) {
        _showError('Голосовое сообщение пустое');
        return;
      }

      final wavBytes = _buildWavBytes(
        Uint8List.fromList(_recordedPcmBytes),
        sampleRate: _voiceSampleRate,
        channels: _voiceChannels,
      );

      final uploaded = await ApiClient.uploadBytes(
        path: '/attachments/upload',
        bytes: wavBytes,
        filename: 'voice_${DateTime.now().millisecondsSinceEpoch}.wav',
        fields: {
          'send_as_file': 'false',
        },
      );

      await _sendMessage(
        attachmentId: uploaded['id']?.toString(),
        clearInput: false,
        manageSendingState: false,
      );

      _recordedPcmBytes.clear();

      if (mounted) {
        TopNotification.success(
          context,
          message: 'Голосовое сообщение отправлено',
        );
      }
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() {
          _recording = false;
          _recordLocked = false;
          _recordingStartedAt = null;
          _recordingElapsed = Duration.zero;
          _voiceLockProgress = 0.0;
          _sending = false;
        });
      }
    }
  }

  Future<void> _cancelVoiceRecording() async {
    if (!_recording) return;

    try {
      _stopRecordingTicker();

      await _recordSubscription?.cancel();
      _recordSubscription = null;
      await _recorder.stop();
      _recordedPcmBytes.clear();

      if (!mounted) return;

      setState(() {
        _recording = false;
        _recordLocked = false;
        _recordingStartedAt = null;
        _recordingElapsed = Duration.zero;
        _voiceLockProgress = 0.0;
      });

      TopNotification.info(
        context,
        message: 'Запись отменена',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Uint8List _buildWavBytes(
    Uint8List pcmBytes, {
    required int sampleRate,
    required int channels,
  }) {
    final byteRate = sampleRate * channels * 2;
    final blockAlign = channels * 2;
    final dataLength = pcmBytes.length;
    final fileLength = 36 + dataLength;

    final header = ByteData(44);

    void writeString(int offset, String value) {
      for (int i = 0; i < value.length; i++) {
        header.setUint8(offset + i, value.codeUnitAt(i));
      }
    }

    writeString(0, 'RIFF');
    header.setUint32(4, fileLength, Endian.little);
    writeString(8, 'WAVE');
    writeString(12, 'fmt ');
    header.setUint32(16, 16, Endian.little);
    header.setUint16(20, 1, Endian.little);
    header.setUint16(22, channels, Endian.little);
    header.setUint32(24, sampleRate, Endian.little);
    header.setUint32(28, byteRate, Endian.little);
    header.setUint16(32, blockAlign, Endian.little);
    header.setUint16(34, 16, Endian.little);
    writeString(36, 'data');
    header.setUint32(40, dataLength, Endian.little);

    final result = Uint8List(44 + dataLength);
    result.setRange(0, 44, header.buffer.asUint8List());
    result.setRange(44, result.length, pcmBytes);

    return result;
  }

// ignore: unused_element
  Future<_MultiAttachmentOptions?> _showMultiAttachmentSheet(
    List<PlatformFile> files,
  ) async {
    final captionController = TextEditingController(
      text: _messageController.text.trim(),
    );

    _AttachmentMode mode = _AttachmentMode.media;

    final result = await showModalBottomSheet<_MultiAttachmentOptions>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (context) {
        final bottom = MediaQuery.of(context).viewInsets.bottom;

        return StatefulBuilder(
          builder: (context, setModalState) {
            return Padding(
              padding: EdgeInsets.fromLTRB(16, 8, 16, bottom + 16),
              child: SafeArea(
                top: false,
                child: SizedBox(
                  height: MediaQuery.of(context).size.height * 0.72,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Text(
                        'Отправить файлы',
                        style: Theme.of(context).textTheme.titleLarge,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Выбрано: ${files.length}',
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                      const SizedBox(height: 12),
                      SegmentedButton<_AttachmentMode>(
                        segments: const [
                          ButtonSegment(
                            value: _AttachmentMode.media,
                            icon: Icon(Icons.perm_media_outlined),
                            label: Text('Медиа'),
                          ),
                          ButtonSegment(
                            value: _AttachmentMode.file,
                            icon: Icon(Icons.insert_drive_file_outlined),
                            label: Text('Файлы'),
                          ),
                        ],
                        selected: {mode},
                        onSelectionChanged: (value) {
                          setModalState(() {
                            mode = value.first;
                          });
                        },
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: captionController,
                        minLines: 1,
                        maxLines: 4,
                        decoration: const InputDecoration(
                          labelText: 'Подпись',
                          hintText: 'Подпись добавится к первому файлу',
                          border: OutlineInputBorder(),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Expanded(
                        child: ListView.builder(
                          itemCount: files.length,
                          itemBuilder: (context, index) {
                            final file = files[index];

                            return Card(
                              margin: const EdgeInsets.symmetric(vertical: 4),
                              child: ListTile(
                                leading: CircleAvatar(
                                  child: Icon(_iconForFile(file.name)),
                                ),
                                title: Text(
                                  file.name,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                subtitle: Text(_formatBytes(file.size)),
                              ),
                            );
                          },
                        ),
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          Expanded(
                            child: OutlinedButton(
                              onPressed: () {
                                Navigator.of(context).pop(null);
                              },
                              child: const Text('Отмена'),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: FilledButton.icon(
                              onPressed: () {
                                Navigator.of(context).pop(
                                  _MultiAttachmentOptions(
                                    mode: mode,
                                    caption: captionController.text,
                                  ),
                                );
                              },
                              icon: const Icon(Icons.send),
                              label: const Text('Отправить'),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            );
          },
        );
      },
    );

    captionController.dispose();

    return result;
  }

  Future<void> _sendMessage({
    String? text,
    String? attachmentId,
    bool clearInput = true,
    bool manageSendingState = true,
  }) async {
    if ((text == null || text.trim().isEmpty) &&
        (attachmentId == null || attachmentId.isEmpty)) {
      return;
    }

    if (manageSendingState) {
      setState(() => _sending = true);
    }

    try {
      final message = await ApiClient.post(
        '/chats/${widget.chatId}/messages',
        {
          'text': text,
          'attachment_id': attachmentId,
        },
      );

      if (clearInput) {
        _messageController.clear();
      }

      if (!mounted) return;

      final exists = _messages.any((item) => item['id'] == message['id']);

      if (!exists) {
        final map = Map<String, dynamic>.from(message as Map);
        map['is_mine'] = true;

        setState(() {
          _messages.add(map);
        });
      }

      _scrollToBottom();
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted && manageSendingState) {
        setState(() => _sending = false);
      }
    }
  }

  Future<void> _openMessageActions(Map<String, dynamic> message) async {
    final isMine = message['is_mine'] == true;
    final canEdit = isMine &&
        message['text'] != null &&
        message['text'].toString().trim().isNotEmpty;
    final hasMyReaction = _hasMyReaction(message);

    final selected = await showModalBottomSheet<String>(
      context: context,
      showDragHandle: true,
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.add_reaction_outlined),
                title: const Text('Реакция emoji'),
                onTap: () => Navigator.of(context).pop('emoji_reaction'),
              ),
              ListTile(
                leading: const Icon(Icons.image_outlined),
                title: const Text('Реакция картинкой'),
                onTap: () => Navigator.of(context).pop('image_reaction'),
              ),
              if (hasMyReaction)
                ListTile(
                  leading: const Icon(Icons.close),
                  title: const Text('Убрать мою реакцию'),
                  onTap: () => Navigator.of(context).pop('remove_reaction'),
                ),
              const Divider(height: 1),
              if (canEdit)
                ListTile(
                  leading: const Icon(Icons.edit),
                  title: const Text('Редактировать'),
                  onTap: () => Navigator.of(context).pop('edit'),
                ),
              if (isMine)
                ListTile(
                  leading: const Icon(Icons.delete_outline),
                  title: const Text('Удалить'),
                  onTap: () => Navigator.of(context).pop('delete'),
                ),
            ],
          ),
        );
      },
    );

    if (selected == 'emoji_reaction') {
      await _pickEmojiReaction(message);
    }

    if (selected == 'image_reaction') {
      await _pickImageReaction(message);
    }

    if (selected == 'remove_reaction') {
      await _removeMyReaction(message);
    }

    if (selected == 'edit') {
      await _editMessage(message);
    }

    if (selected == 'delete') {
      await _deleteMessage(message);
    }
  }

  bool _hasMyReaction(Map<String, dynamic> message) {
    final reactions = message['reactions'];

    if (reactions is! List) return false;

    return reactions.any(
      (item) => item is Map && item['user_id']?.toString() == _myUserId,
    );
  }

  Future<void> _pickEmojiReaction(Map<String, dynamic> message) async {
    final controller = TextEditingController();
    const quickEmojis = ['👍', '❤️', '😂', '🔥', '🥰', '😮', '😢', '👏'];

    final selected = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (context) {
        final bottom = MediaQuery.of(context).viewInsets.bottom;

        return Padding(
          padding: EdgeInsets.fromLTRB(16, 8, 16, bottom + 16),
          child: SafeArea(
            top: false,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Выберите реакцию',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: quickEmojis.map((emoji) {
                    return InkWell(
                      borderRadius: BorderRadius.circular(18),
                      onTap: () => Navigator.of(context).pop(emoji),
                      child: Container(
                        width: 54,
                        height: 54,
                        alignment: Alignment.center,
                        decoration: BoxDecoration(
                          color: Theme.of(context)
                              .colorScheme
                              .surfaceContainerHighest,
                          borderRadius: BorderRadius.circular(18),
                        ),
                        child: Text(
                          emoji,
                          style: const TextStyle(fontSize: 26),
                        ),
                      ),
                    );
                  }).toList(),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: controller,
                  autofocus: true,
                  decoration: const InputDecoration(
                    labelText: 'Любой emoji или символ',
                    border: OutlineInputBorder(),
                  ),
                  onSubmitted: (value) {
                    final text = value.trim();
                    if (text.isNotEmpty) Navigator.of(context).pop(text);
                  },
                ),
                const SizedBox(height: 12),
                FilledButton.icon(
                  onPressed: () {
                    final text = controller.text.trim();
                    if (text.isNotEmpty) Navigator.of(context).pop(text);
                  },
                  icon: const Icon(Icons.check),
                  label: const Text('Поставить'),
                ),
              ],
            ),
          ),
        );
      },
    );

    controller.dispose();

    if (selected == null || selected.trim().isEmpty) return;

    await _setEmojiReaction(message, selected.trim());
  }

  Future<void> _setEmojiReaction(
    Map<String, dynamic> message,
    String emoji,
  ) async {
    try {
      final reaction = await ApiClient.post(
        '/messages/${message['id']}/reaction',
        {
          'reaction_type': 'emoji',
          'emoji': emoji,
        },
      );

      if (!mounted) return;

      _applyReactionToLocalMessage(
        message['id']?.toString(),
        Map<String, dynamic>.from(reaction as Map),
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _pickImageReaction(Map<String, dynamic> message) async {
    try {
      final result = await FilePicker.pickFiles(
        withData: true,
        allowMultiple: false,
        type: FileType.image,
      );

      if (result == null || result.files.isEmpty) return;

      final file = result.files.first;
      final bytes = file.bytes;

      if (bytes == null) {
        _showError('Не удалось прочитать изображение');
        return;
      }

      setState(() => _sending = true);

      final uploaded = await ApiClient.uploadBytes(
        path: '/attachments/upload',
        bytes: bytes,
        filename: file.name,
        fields: const {
          'send_as_file': 'false',
        },
      );

      final reaction = await ApiClient.post(
        '/messages/${message['id']}/reaction',
        {
          'reaction_type': 'image',
          'attachment_id': uploaded['id']?.toString(),
        },
      );

      if (!mounted) return;

      _applyReactionToLocalMessage(
        message['id']?.toString(),
        Map<String, dynamic>.from(reaction as Map),
      );

      TopNotification.success(
        context,
        message: 'Реакция-картинка добавлена',
      );
    } catch (e) {
      _showError(_cleanError(e));
    } finally {
      if (mounted) {
        setState(() => _sending = false);
      }
    }
  }

  Future<void> _removeMyReaction(Map<String, dynamic> message) async {
    final messageId = message['id']?.toString();

    if (messageId == null) return;

    try {
      await ApiClient.post(
        '/messages/$messageId/reaction/delete',
        {},
      );

      if (!mounted) return;

      setState(() {
        final index = _messages.indexWhere(
          (item) => item['id']?.toString() == messageId,
        );

        if (index == -1) return;

        final updated = Map<String, dynamic>.from(_messages[index] as Map);
        final reactions = updated['reactions'] is List
            ? List<dynamic>.from(updated['reactions'] as List)
            : <dynamic>[];

        reactions.removeWhere(
          (item) => item is Map && item['user_id']?.toString() == _myUserId,
        );

        updated['reactions'] = reactions;
        _messages[index] = updated;
      });
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  void _applyReactionToLocalMessage(
    String? messageId,
    Map<String, dynamic> reaction,
  ) {
    if (messageId == null) return;

    setState(() {
      final index = _messages.indexWhere(
        (item) => item['id']?.toString() == messageId,
      );

      if (index == -1) return;

      final updated = Map<String, dynamic>.from(_messages[index] as Map);
      final reactions = updated['reactions'] is List
          ? List<dynamic>.from(updated['reactions'] as List)
          : <dynamic>[];
      final reactionUserId = reaction['user_id']?.toString();

      reactions.removeWhere(
        (item) => item is Map && item['user_id']?.toString() == reactionUserId,
      );

      reactions.add({
        ...reaction,
        'is_mine': reactionUserId == _myUserId,
      });

      updated['reactions'] = reactions;
      _messages[index] = updated;
    });
  }

  Future<void> _editMessage(Map<String, dynamic> message) async {
    final controller = TextEditingController(
      text: message['text']?.toString() ?? '',
    );

    final result = await showDialog<String>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Редактировать сообщение'),
          content: TextField(
            controller: controller,
            autofocus: true,
            minLines: 1,
            maxLines: 5,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              labelText: 'Текст',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(null),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () {
                final text = controller.text.trim();

                if (text.isEmpty) return;

                Navigator.of(context).pop(text);
              },
              child: const Text('Сохранить'),
            ),
          ],
        );
      },
    );

    controller.dispose();

    if (result == null || result.trim().isEmpty) return;

    try {
      final updated = await ApiClient.post(
        '/messages/${message['id']}/edit',
        {
          'text': result.trim(),
        },
      );

      if (!mounted) return;

      setState(() {
        final index = _messages.indexWhere(
          (item) => item['id'] == message['id'],
        );

        if (index != -1) {
          final old = Map<String, dynamic>.from(_messages[index] as Map);
          _messages[index] = {
            ...old,
            ...Map<String, dynamic>.from(updated as Map),
            'is_mine': true,
          };
        }
      });

      TopNotification.success(
        context,
        message: 'Сообщение изменено',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _deleteMessage(Map<String, dynamic> message) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Удалить сообщение?'),
          content: const Text('Сообщение исчезнет из чата.'),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Удалить'),
            ),
          ],
        );
      },
    );

    if (confirm != true) return;

    try {
      await ApiClient.post(
        '/messages/${message['id']}/delete',
        {},
      );

      if (!mounted) return;

      setState(() {
        _messages.removeWhere((item) => item['id'] == message['id']);
      });

      TopNotification.success(
        context,
        message: 'Сообщение удалено',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

// ignore: unused_element
  IconData _iconForFile(String filename) {
    final lower = filename.toLowerCase();

    if (lower.endsWith('.jpg') ||
        lower.endsWith('.jpeg') ||
        lower.endsWith('.png') ||
        lower.endsWith('.webp') ||
        lower.endsWith('.gif')) {
      return Icons.image_outlined;
    }

    if (lower.endsWith('.mp4') ||
        lower.endsWith('.mov') ||
        lower.endsWith('.avi') ||
        lower.endsWith('.mkv') ||
        lower.endsWith('.webm')) {
      return Icons.play_circle_outline;
    }

    if (lower.endsWith('.mp3') ||
        lower.endsWith('.wav') ||
        lower.endsWith('.m4a') ||
        lower.endsWith('.aac') ||
        lower.endsWith('.ogg')) {
      return Icons.graphic_eq;
    }

    if (lower.endsWith('.pdf')) {
      return Icons.picture_as_pdf_outlined;
    }

    return Icons.insert_drive_file_outlined;
  }

// ignore: unused_element
  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';

    final kb = bytes / 1024;
    if (kb < 1024) return '${kb.toStringAsFixed(1)} KB';

    final mb = kb / 1024;
    if (mb < 1024) return '${mb.toStringAsFixed(1)} MB';

    final gb = mb / 1024;
    return '${gb.toStringAsFixed(1)} GB';
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;

      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOut,
      );
    });
  }

  String _cleanError(Object e) {
    return e.toString().replaceFirst('Exception: ', '');
  }

  void _showError(String message) {
    if (!mounted) return;

    TopNotification.error(
      context,
      message: message,
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

  BoxDecoration _wallpaperDecoration(BuildContext context) {
    final accent = _accentColorValue();
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final isCustomImage = _chatWallpaper.startsWith('/uploads/') ||
        _chatWallpaper.startsWith('http://') ||
        _chatWallpaper.startsWith('https://');

    if (isCustomImage) {
      return BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        image: DecorationImage(
          image: NetworkImage(ApiClient.absoluteUrl(_chatWallpaper)),
          fit: BoxFit.cover,
          colorFilter: ColorFilter.mode(
            Colors.black.withValues(alpha: 0.38),
            BlendMode.darken,
          ),
        ),
      );
    }

    switch (_chatWallpaper) {
      case 'clean':
        return BoxDecoration(
          color: isDark ? const Color(0xFF0B141A) : Theme.of(context).colorScheme.surfaceContainerHighest,
        );

      case 'gradient':
        return BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              accent.withValues(alpha: 0.25),
              Theme.of(context).colorScheme.surface,
              accent.withValues(alpha: 0.12),
            ],
          ),
        );

      case 'night':
        return const BoxDecoration(
          gradient: LinearGradient(
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
        return const BoxDecoration(
          gradient: LinearGradient(
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
          color: isDark ? const Color(0xFF0B141A) : const Color(0xFFECE5DD),
        );
    }
  }

  Future<void> _openGroupInfo() async {
    if (!widget.isGroup) return;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (sheetContext) {
        return _GroupInfoSheet(
          title: _title,
          chatId: widget.chatId,
          accent: _accentColorValue(),
          onRename: _renameGroup,
          onPickAvatar: _pickGroupAvatar,
          onAddMembers: _openAddMembers,
          onLeave: _leaveGroup,
        );
      },
    );
  }

  Future<void> _renameGroup() async {
    final controller = TextEditingController(text: _title);

    final result = await showDialog<String>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Название группы'),
          content: TextField(
            controller: controller,
            autofocus: true,
            maxLength: 120,
            decoration: const InputDecoration(
              labelText: 'Название',
              border: OutlineInputBorder(),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(null),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () {
                final text = controller.text.trim();
                if (text.isEmpty) return;
                Navigator.of(context).pop(text);
              },
              child: const Text('Сохранить'),
            ),
          ],
        );
      },
    );

    controller.dispose();

    if (result == null || result.trim().isEmpty) return;

    try {
      await ApiClient.post(
        '/chats/${widget.chatId}/title',
        {'title': result.trim()},
      );

      if (!mounted) return;

      setState(() => _title = result.trim());

      TopNotification.success(
        context,
        message: 'Название группы изменено',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _pickGroupAvatar() async {
    try {
      final result = await FilePicker.pickFiles(
        withData: true,
        allowMultiple: false,
        type: FileType.image,
      );

      if (result == null || result.files.isEmpty) return;

      final file = result.files.first;
      final bytes = file.bytes;

      if (bytes == null) {
        _showError('Не удалось прочитать изображение');
        return;
      }

      await ApiClient.uploadBytes(
        path: '/chats/${widget.chatId}/avatar',
        bytes: bytes,
        filename: file.name,
      );

      if (!mounted) return;

      TopNotification.success(
        context,
        message: 'Аватар группы обновлён',
      );
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  Future<void> _openAddMembers() async {
    final added = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (context) {
        return _AddMembersSheet(chatId: widget.chatId);
      },
    );

    if (added == true && mounted) {
      TopNotification.success(
        context,
        message: 'Участники добавлены',
      );
    }
  }

  Future<void> _leaveGroup() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Выйти из группы?'),
          content: const Text('Группа исчезнет из списка ваших чатов.'),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Выйти'),
            ),
          ],
        );
      },
    );

    if (confirm != true) return;

    try {
      await ApiClient.post('/chats/${widget.chatId}/leave', {});

      if (!mounted) return;

      Navigator.of(context).pop();
      Navigator.of(context).pop();
    } catch (e) {
      _showError(_cleanError(e));
    }
  }

  @override
  void dispose() {
    _messageController.dispose();
    _scrollController.dispose();
    _wsSubscription?.cancel();
    _recordSubscription?.cancel();
    _recordingTicker?.cancel();
    _recorder.dispose();
    _ws.dispose();
    super.dispose();
  }

  List<String> _voicePlaybackUrls(List<dynamic> messages) {
    final urls = <String>[];

    for (final item in messages) {
      if (item is! Map) continue;

      final message = Map<String, dynamic>.from(item);
      final rawAttachment = message['attachment'];

      if (rawAttachment is! Map) continue;

      final attachment = Map<String, dynamic>.from(rawAttachment);
      final kind = attachment['kind']?.toString();
      final rawUrl = attachment['url']?.toString();

      if (kind != 'audio') continue;
      if (rawUrl == null || rawUrl.trim().isEmpty) continue;

      urls.add(ApiClient.absoluteUrl(rawUrl));
    }

    return urls;
  }

  @override
  Widget build(BuildContext context) {
    final messages = _messages;
    VoicePlaybackQueue.setUrls(_voicePlaybackUrls(messages));
    final accent = _accentColorValue();
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final chatBackgroundColor = isDark ? const Color(0xFF0B141A) : const Color(0xFFECE5DD);
    final inputBarColor = isDark ? const Color(0xFF1F2C34) : const Color(0xFFF0F0F0);
    final inputFillColor = isDark ? const Color(0xFF2A3942) : Colors.white;
    final inputTextColor = isDark ? const Color(0xFFE9EDEF) : const Color(0xFF111111);
    final inputHintColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF9AA0A6);
    final inputBorderColor = isDark ? const Color(0xFF2A3942) : Theme.of(context).colorScheme.outlineVariant.withValues(alpha: 0.5);

    return Scaffold(
      backgroundColor: chatBackgroundColor,
      appBar: AppBar(
        backgroundColor: accent,
        foregroundColor: Colors.white,
        elevation: 0,
        titleSpacing: 0,
        title: Row(
          children: [
            CircleAvatar(
              radius: 18,
              backgroundColor: Colors.white.withValues(alpha: 0.20),
              foregroundColor: Colors.white,
              child: Icon(
                widget.isGroup ? Icons.groups_rounded : Icons.person_rounded,
                size: 21,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _title,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                  fontWeight: FontWeight.w800,
                  fontSize: 18,
                ),
              ),
            ),
          ],
        ),
        actions: [
          if (widget.isGroup)
            IconButton(
              tooltip: 'Информация о группе',
              onPressed: _openGroupInfo,
              icon: const Icon(Icons.more_vert_rounded),
            ),
        ],
      ),
      body: DecoratedBox(
        decoration: _wallpaperDecoration(context),
        child: Column(
          children: [
            Expanded(
              child: RefreshIndicator(
                onRefresh: () async {
                  await _loadMe();
                  await _loadMessages();
                },
                child: _loading
                    ? ListView(
                        children: const [
                          SizedBox(height: 220),
                          Center(child: CircularProgressIndicator()),
                        ],
                      )
                    : messages.isEmpty
                        ? ListView(
                            children: const [
                              SizedBox(height: 220),
                              Center(
                                child: Text('Пока нет сообщений'),
                              ),
                            ],
                          )
                        : ListView.builder(
                            controller: _scrollController,
                            cacheExtent: 1400,
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            itemCount: messages.length,
                            itemBuilder: (context, index) {
                              final message = Map<String, dynamic>.from(
                                messages[index] as Map,
                              );

                              return MessageBubble(
                                text: message['text']?.toString(),
                                attachment: message['attachment'] == null
                                    ? null
                                    : Map<String, dynamic>.from(
                                        message['attachment'] as Map,
                                      ),
                                senderName: message['sender_name']?.toString(),
                                isMine: message['is_mine'] == true,
                                editedAt: message['edited_at']?.toString(),
                                reactions: message['reactions'] is List
                                    ? List<dynamic>.from(message['reactions'] as List)
                                    : const [],
                                accentColor: accent,
                                bubbleStyle: _bubbleStyle,
                                onLongPress: () => _openMessageActions(message),
                              );
                            },
                          ),
              ),
            ),
            SafeArea(
              top: false,
              child: Container(
                padding: const EdgeInsets.fromLTRB(8, 8, 8, 12),
                decoration: BoxDecoration(
                  color: inputBarColor,
                  border: Border(
                    top: BorderSide(
                      color: inputBorderColor,
                    ),
                  ),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (_recording)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: _VoiceRecordingPanel(
                          accent: accent,
                          locked: _recordLocked,
                          elapsed: _recordingElapsed,
                          lockProgress: _voiceLockProgress,
                          onLock: _lockVoiceRecording,
                          onCancel: _cancelVoiceRecording,
                        ),
                      ),
                    Row(
                      children: [
                        IconButton(
                          tooltip: 'Прикрепить файлы',
                          onPressed: _sending || _recording
                              ? null
                              : _openInternalFileManager,
                          color: accent,
                          icon: const Icon(Icons.attach_file),
                        ),
                        Expanded(
                          child: TextField(
                            controller: _messageController,
                            enabled: !_recording,
                            style: TextStyle(color: inputTextColor),
                            cursorColor: accent,
                            minLines: 1,
                            maxLines: 4,
                            textInputAction: TextInputAction.send,
                            onSubmitted: (_) {
                              if (!_sending && !_recording) _sendTextMessage();
                            },
                            decoration: InputDecoration(
                              hintText: _recording
                                  ? (_recordLocked
                                      ? 'Автозапись идёт'
                                      : 'Потяните вверх для автозаписи')
                                  : 'Сообщение',
                              filled: true,
                              fillColor: inputFillColor,
                              hintStyle: TextStyle(color: inputHintColor),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(24),
                                borderSide: BorderSide.none,
                              ),
                              isDense: true,
                              contentPadding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 11,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        if (_hasTextInput && !_recording)
                          _RoundActionButton(
                            accent: accent,
                            disabled: _sending,
                            icon: Icons.send_rounded,
                            loading: _sending,
                            onTap: _sendTextMessage,
                          )
                        else
                          _HoldToRecordButton(
                            accent: accent,
                            recording: _recording,
                            locked: _recordLocked,
                            lockProgress: _voiceLockProgress,
                            disabled: _sending,
                            onTap: _handleMicTap,
                            onLongPressStart: _handleMicLongPressStart,
                            onLongPressMoveUpdate: _handleMicLongPressMoveUpdate,
                            onLongPressEnd: _handleMicLongPressEnd,
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
    );
  }
}


class _VoiceRecordingPanel extends StatelessWidget {
  final Color accent;
  final bool locked;
  final Duration elapsed;
  final double lockProgress;
  final VoidCallback onLock;
  final VoidCallback onCancel;

  const _VoiceRecordingPanel({
    required this.accent,
    required this.locked,
    required this.elapsed,
    required this.lockProgress,
    required this.onLock,
    required this.onCancel,
  });

  String _elapsedText() {
    final minutes = elapsed.inMinutes.remainder(60).toString().padLeft(2, '0');
    final seconds = elapsed.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final panelColor = isDark ? const Color(0xFF1F2C34) : const Color(0xFFE8F5E9);
    final textColor = isDark ? const Color(0xFFE9EDEF) : const Color(0xFF111111);
    final subColor = isDark ? const Color(0xFF8696A0) : const Color(0xFF5F6368);
    final progress = lockProgress.clamp(0.0, 1.0);

    return AnimatedContainer(
      duration: const Duration(milliseconds: 140),
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(10, 8, 8, 8),
      decoration: BoxDecoration(
        color: panelColor,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: accent.withValues(alpha: locked ? 0.40 : 0.18 + progress * 0.22),
        ),
      ),
      child: Row(
        children: [
          AnimatedContainer(
            duration: const Duration(milliseconds: 140),
            width: 38,
            height: 38,
            decoration: BoxDecoration(
              color: locked ? accent : Color.lerp(Colors.redAccent, accent, progress),
              shape: BoxShape.circle,
            ),
            child: Icon(
              locked ? Icons.lock_rounded : Icons.mic_rounded,
              color: Colors.white,
              size: 21,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  locked ? 'Автозапись включена' : 'Идёт запись голосового',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: textColor,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  locked
                      ? '${_elapsedText()} · нажмите микрофон, чтобы отправить'
                      : '${_elapsedText()} · отпустите для отправки или потяните вверх',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: subColor,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
          if (!locked)
            IconButton(
              tooltip: 'Закрепить запись',
              onPressed: onLock,
              color: accent,
              icon: const Icon(Icons.lock_open_rounded),
            ),
          IconButton(
            tooltip: 'Отменить запись',
            onPressed: onCancel,
            color: Colors.redAccent,
            icon: const Icon(Icons.delete_outline_rounded),
          ),
        ],
      ),
    );
  }
}

class _RoundActionButton extends StatelessWidget {
  final Color accent;
  final IconData icon;
  final bool disabled;
  final bool loading;
  final VoidCallback onTap;

  const _RoundActionButton({
    required this.accent,
    required this.icon,
    required this.disabled,
    required this.loading,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: disabled ? null : onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 140),
        width: 48,
        height: 48,
        decoration: BoxDecoration(
          color: disabled ? accent.withValues(alpha: 0.45) : accent,
          shape: BoxShape.circle,
        ),
        child: Center(
          child: loading
              ? const SizedBox(
                  width: 19,
                  height: 19,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.2,
                    color: Colors.white,
                  ),
                )
              : Icon(
                  icon,
                  color: Colors.white,
                  size: 25,
                ),
        ),
      ),
    );
  }
}

class _HoldToRecordButton extends StatelessWidget {
  final Color accent;
  final bool recording;
  final bool locked;
  final double lockProgress;
  final bool disabled;
  final VoidCallback onTap;
  final GestureLongPressStartCallback onLongPressStart;
  final GestureLongPressMoveUpdateCallback onLongPressMoveUpdate;
  final GestureLongPressEndCallback onLongPressEnd;

  const _HoldToRecordButton({
    required this.accent,
    required this.recording,
    required this.locked,
    required this.lockProgress,
    required this.disabled,
    required this.onTap,
    required this.onLongPressStart,
    required this.onLongPressMoveUpdate,
    required this.onLongPressEnd,
  });

  @override
  Widget build(BuildContext context) {
    final progress = lockProgress.clamp(0.0, 1.0);
    final color = recording ? (locked ? accent : Colors.redAccent) : accent;
    final scale = recording ? 1.08 : 1.0;

    return SizedBox(
      width: 58,
      height: 96,
      child: Stack(
        clipBehavior: Clip.none,
        alignment: Alignment.bottomCenter,
        children: [
          Positioned(
            bottom: 56 + 42 * progress,
            child: IgnorePointer(
              child: AnimatedOpacity(
                duration: const Duration(milliseconds: 120),
                opacity: recording && !locked ? (0.28 + progress * 0.72) : 0.0,
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 120),
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: progress >= 0.88 ? accent : const Color(0xFF1F2C34),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.22),
                        blurRadius: 12,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: Icon(
                    progress >= 0.88 ? Icons.lock_rounded : Icons.keyboard_arrow_up_rounded,
                    color: Colors.white,
                    size: 25,
                  ),
                ),
              ),
            ),
          ),
          Positioned(
            bottom: 0,
            child: GestureDetector(
              onTap: disabled ? null : onTap,
              onLongPressStart: disabled ? null : onLongPressStart,
              onLongPressMoveUpdate: disabled ? null : onLongPressMoveUpdate,
              onLongPressEnd: disabled ? null : onLongPressEnd,
              child: AnimatedScale(
                duration: const Duration(milliseconds: 140),
                scale: scale,
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 160),
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: disabled ? color.withValues(alpha: 0.45) : color,
                    shape: BoxShape.circle,
                    boxShadow: [
                      if (recording)
                        BoxShadow(
                          color: color.withValues(alpha: 0.38),
                          blurRadius: 18,
                          spreadRadius: 2,
                        ),
                    ],
                  ),
                  child: Icon(
                    recording ? Icons.mic_rounded : Icons.mic_rounded,
                    color: Colors.white,
                    size: 26,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _GroupInfoSheet extends StatelessWidget {
  final String title;
  final String chatId;
  final Color accent;
  final Future<void> Function() onRename;
  final Future<void> Function() onPickAvatar;
  final Future<void> Function() onAddMembers;
  final Future<void> Function() onLeave;

  const _GroupInfoSheet({
    required this.title,
    required this.chatId,
    required this.accent,
    required this.onRename,
    required this.onPickAvatar,
    required this.onAddMembers,
    required this.onLeave,
  });

  Future<List<dynamic>> _loadMembers() async {
    final result = await ApiClient.get('/chats/$chatId/members');
    return result is List ? result : [];
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      top: false,
      child: SizedBox(
        height: MediaQuery.of(context).size.height * 0.78,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  CircleAvatar(
                    radius: 26,
                    backgroundColor: accent.withValues(alpha: 0.16),
                    child: Icon(
                      Icons.groups_2_outlined,
                      color: accent,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: Theme.of(context).textTheme.titleLarge?.copyWith(
                                fontWeight: FontWeight.w900,
                              ),
                        ),
                        Text(
                          'Групповой чат',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton.icon(
                    onPressed: onRename,
                    icon: const Icon(Icons.edit_outlined),
                    label: const Text('Название'),
                  ),
                  OutlinedButton.icon(
                    onPressed: onPickAvatar,
                    icon: const Icon(Icons.image_outlined),
                    label: const Text('Аватар'),
                  ),
                  OutlinedButton.icon(
                    onPressed: onAddMembers,
                    icon: const Icon(Icons.person_add_alt_1_outlined),
                    label: const Text('Добавить'),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Text(
                'Участники',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Expanded(
                child: FutureBuilder<List<dynamic>>(
                  future: _loadMembers(),
                  builder: (context, snapshot) {
                    if (snapshot.connectionState != ConnectionState.done) {
                      return const Center(child: CircularProgressIndicator());
                    }

                    final members = snapshot.data ?? [];

                    if (members.isEmpty) {
                      return const Center(child: Text('Участники не найдены'));
                    }

                    return ListView.builder(
                      itemCount: members.length,
                      itemBuilder: (context, index) {
                        final member = Map<String, dynamic>.from(members[index] as Map);
                        final name = member['name']?.toString() ?? 'Пользователь';
                        final username = member['username']?.toString() ?? '';
                        final avatarUrl = member['avatar_url']?.toString();
                        final role = member['role']?.toString() ?? 'member';

                        return Card(
                          child: ListTile(
                            leading: CircleAvatar(
                              backgroundColor: accent.withValues(alpha: 0.16),
                              backgroundImage: avatarUrl == null || avatarUrl.isEmpty
                                  ? null
                                  : NetworkImage(ApiClient.absoluteUrl(avatarUrl)),
                              child: avatarUrl == null || avatarUrl.isEmpty
                                  ? Text(name.characters.first.toUpperCase())
                                  : null,
                            ),
                            title: Text(name),
                            subtitle: Text(
                              username.isEmpty ? role : '@$username · $role',
                            ),
                          ),
                        );
                      },
                    );
                  },
                ),
              ),
              const SizedBox(height: 10),
              OutlinedButton.icon(
                onPressed: onLeave,
                icon: const Icon(Icons.logout),
                label: const Text('Выйти из группы'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AddMembersSheet extends StatefulWidget {
  final String chatId;

  const _AddMembersSheet({required this.chatId});

  @override
  State<_AddMembersSheet> createState() => _AddMembersSheetState();
}

class _AddMembersSheetState extends State<_AddMembersSheet> {
  final _queryController = TextEditingController();

  Timer? _debounce;
  bool _searching = false;
  bool _saving = false;
  List<dynamic> _results = [];
  final Map<String, Map<String, dynamic>> _selected = {};

  @override
  void dispose() {
    _debounce?.cancel();
    _queryController.dispose();
    super.dispose();
  }

  void _onChanged(String value) {
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
      setState(() => _results = []);
      return;
    }

    setState(() => _searching = true);

    try {
      final result = await ApiClient.get(
        '/users/search?q=${Uri.encodeQueryComponent(query)}',
      );

      if (!mounted) return;
      setState(() => _results = result is List ? result : []);
    } finally {
      if (mounted) {
        setState(() => _searching = false);
      }
    }
  }

  String _title(Map<String, dynamic> user) {
    final displayName = user['display_name']?.toString().trim();
    if (displayName != null && displayName.isNotEmpty) return displayName;

    final nickname = user['nickname']?.toString().trim();
    if (nickname != null && nickname.isNotEmpty) return nickname;

    return user['username']?.toString() ?? 'Пользователь';
  }

  void _toggle(Map<String, dynamic> user) {
    final id = user['id']?.toString();
    if (id == null || id.isEmpty) return;

    setState(() {
      if (_selected.containsKey(id)) {
        _selected.remove(id);
      } else {
        _selected[id] = user;
      }
    });
  }

  Future<void> _save() async {
    if (_selected.isEmpty) return;

    setState(() => _saving = true);

    try {
      await ApiClient.post(
        '/chats/${widget.chatId}/members',
        {'user_ids': _selected.keys.toList()},
      );

      if (!mounted) return;
      Navigator.of(context).pop(true);
    } finally {
      if (mounted) {
        setState(() => _saving = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final bottom = MediaQuery.of(context).viewInsets.bottom;
    final accent = Theme.of(context).colorScheme.primary;

    return Padding(
      padding: EdgeInsets.fromLTRB(16, 8, 16, bottom + 16),
      child: SafeArea(
        top: false,
        child: SizedBox(
          height: MediaQuery.of(context).size.height * 0.75,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      'Добавить участников',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                  FilledButton(
                    onPressed: _saving || _selected.isEmpty ? null : _save,
                    child: _saving
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : Text('Добавить (${_selected.length})'),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _queryController,
                enabled: !_saving,
                onChanged: _onChanged,
                decoration: InputDecoration(
                  labelText: 'Найти пользователей',
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
                          final user = Map<String, dynamic>.from(_results[index] as Map);
                          final id = user['id']?.toString() ?? '';
                          final selected = _selected.containsKey(id);
                          final name = _title(user);
                          final username = user['username']?.toString() ?? '';
                          final avatarUrl = user['avatar_url']?.toString();

                          return Card(
                            child: ListTile(
                              onTap: _saving ? null : () => _toggle(user),
                              leading: CircleAvatar(
                                backgroundImage: avatarUrl == null || avatarUrl.isEmpty
                                    ? null
                                    : NetworkImage(ApiClient.absoluteUrl(avatarUrl)),
                                child: avatarUrl == null || avatarUrl.isEmpty
                                    ? Text(name.characters.first.toUpperCase())
                                    : null,
                              ),
                              title: Text(name),
                              subtitle: username.isEmpty ? null : Text('@$username'),
                              trailing: Icon(
                                selected ? Icons.check_circle : Icons.add_circle_outline,
                                color: selected ? accent : null,
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

// ignore: unused_element
class _MultiAttachmentOptions {
  final _AttachmentMode mode;
  final String caption;

  const _MultiAttachmentOptions({
    required this.mode,
    required this.caption,
  });
}
