// ignore_for_file: avoid_web_libraries_in_flutter

import 'dart:js_interop';

@JS('umeOneSignalInit')
external JSPromise<JSAny?> _umeOneSignalInit(String appId);

@JS('umeOneSignalLogin')
external JSPromise<JSAny?> _umeOneSignalLogin(String userId);

@JS('umeOneSignalRequestPermission')
external JSPromise<JSAny?> _umeOneSignalRequestPermission();

@JS('umeOneSignalLogout')
external JSPromise<JSAny?> _umeOneSignalLogout();

Future<void> oneSignalWebInit(String appId) async {
  await _umeOneSignalInit(appId).toDart;
}

Future<void> oneSignalWebLogin(String userId) async {
  await _umeOneSignalLogin(userId).toDart;
}

Future<bool> oneSignalWebRequestPermission() async {
  await _umeOneSignalRequestPermission().toDart;
  return true;
}

Future<void> oneSignalWebLogout() async {
  await _umeOneSignalLogout().toDart;
}