importScripts('https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.13.2/firebase-messaging-compat.js');

firebase.initializeApp({
    apiKey: 'AIzaSyD7aYgl-VDiiL9P0J3YPfAa24g0tjUkAa8',
    appId: '1:62135047180:web:3c6b0030c55af3ea89ca29',
    messagingSenderId: '62135047180',
    projectId: 'ume-messenger-bd3b1',
    authDomain: 'ume-messenger-bd3b1.firebaseapp.com',
    storageBucket: 'ume-messenger-bd3b1.firebasestorage.app',
    measurementId: 'G-MJZEF3RCPX',
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  const notificationTitle =
    payload.notification?.title ||
    payload.data?.title ||
    'UMe Messenger';

  const notificationOptions = {
    body:
      payload.notification?.body ||
      payload.data?.body ||
      'Новое сообщение',
    icon: '/UMe/icons/Icon-192.png',
    badge: '/UMe/icons/Icon-192.png',
    data: payload.data || {},
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});