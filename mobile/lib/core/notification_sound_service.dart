import 'dart:async';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:audioplayers/audioplayers.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class NotificationSoundService {
  static const _storage = FlutterSecureStorage();
  static const _enabledKey = 'ume_notification_sound_enabled';

  static bool _initialized = false;
  static bool _enabled = true;
  static AudioPlayer? _player;

  static bool get enabled => _enabled;

  static Future<void> init() async {
    if (_initialized) return;

    try {
      final value = await _storage.read(key: _enabledKey);
      _enabled = value != 'false';
    } catch (_) {
      _enabled = true;
    }

    _initialized = true;
  }

  static Future<void> setEnabled(bool value) async {
    _enabled = value;
    _initialized = true;

    try {
      await _storage.write(key: _enabledKey, value: value ? 'true' : 'false');
    } catch (_) {}
  }

  static Future<void> playMessageSound({bool force = false}) async {
    await init();

    if (!_enabled && !force) return;

    try {
      final player = _player ??= AudioPlayer();
      await player.stop();
      await player.setReleaseMode(ReleaseMode.stop);
      await player.play(BytesSource(_notificationWavBytes()));
    } catch (_) {
      // Звук уведомления не должен ломать получение сообщений.
    }
  }

  static Future<void> testSound() {
    return playMessageSound(force: true);
  }

  static Uint8List _notificationWavBytes() {
    const sampleRate = 44100;
    const bitsPerSample = 16;
    const channels = 1;

    final samples = <int>[];

    void addTone(double frequency, int milliseconds, double volume) {
      final count = (sampleRate * milliseconds / 1000).round();

      for (var i = 0; i < count; i++) {
        final t = i / sampleRate;
        final fadeIn = math.min(1.0, i / (sampleRate * 0.01));
        final fadeOut = math.min(1.0, (count - i) / (sampleRate * 0.02));
        final envelope = math.min(fadeIn, fadeOut);
        final value = math.sin(2 * math.pi * frequency * t) * volume * envelope;
        samples.add((value * 32767).round().clamp(-32768, 32767));
      }
    }

    void addSilence(int milliseconds) {
      final count = (sampleRate * milliseconds / 1000).round();
      samples.addAll(List<int>.filled(count, 0));
    }

    addTone(880, 90, 0.24);
    addSilence(45);
    addTone(1175, 105, 0.22);

    final dataLength = samples.length * 2;
    final fileLength = 36 + dataLength;
    final byteRate = sampleRate * channels * bitsPerSample ~/ 8;
    final blockAlign = channels * bitsPerSample ~/ 8;

    final bytes = Uint8List(44 + dataLength);
    final data = ByteData.view(bytes.buffer);

    void writeString(int offset, String value) {
      for (var i = 0; i < value.length; i++) {
        data.setUint8(offset + i, value.codeUnitAt(i));
      }
    }

    writeString(0, 'RIFF');
    data.setUint32(4, fileLength, Endian.little);
    writeString(8, 'WAVE');
    writeString(12, 'fmt ');
    data.setUint32(16, 16, Endian.little);
    data.setUint16(20, 1, Endian.little);
    data.setUint16(22, channels, Endian.little);
    data.setUint32(24, sampleRate, Endian.little);
    data.setUint32(28, byteRate, Endian.little);
    data.setUint16(32, blockAlign, Endian.little);
    data.setUint16(34, bitsPerSample, Endian.little);
    writeString(36, 'data');
    data.setUint32(40, dataLength, Endian.little);

    var offset = 44;
    for (final sample in samples) {
      data.setInt16(offset, sample, Endian.little);
      offset += 2;
    }

    return bytes;
  }
}
