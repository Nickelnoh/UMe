import 'package:flutter/material.dart';

import '../core/api_client.dart';

class ChatTile extends StatelessWidget {
  final String title;
  final String subtitle;
  final String? avatarUrl;
  final VoidCallback onTap;
  final VoidCallback? onLongPress;

  const ChatTile({
    super.key,
    required this.title,
    required this.subtitle,
    this.avatarUrl,
    required this.onTap,
    this.onLongPress,
  });

  String _firstLetter(String value) {
    final text = value.trim();

    if (text.isEmpty) return '?';

    return text.characters.first.toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    final resolvedAvatarUrl = ApiClient.absoluteUrl(avatarUrl);

    return ListTile(
      onTap: onTap,
      onLongPress: onLongPress,
      leading: CircleAvatar(
        radius: 23,
        backgroundImage:
            resolvedAvatarUrl.isEmpty ? null : NetworkImage(resolvedAvatarUrl),
        child: resolvedAvatarUrl.isEmpty
            ? Text(
                _firstLetter(title),
                style: const TextStyle(fontWeight: FontWeight.w700),
              )
            : null,
      ),
      title: Text(
        title,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: Text(
        subtitle,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: const Icon(Icons.chevron_right),
    );
  }
}