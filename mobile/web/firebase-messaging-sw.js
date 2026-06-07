importScripts('https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.13.2/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: 'AIzaSyD7aYgl-VDiiL9P0J3YPfAa24g0tjUkAa8',
  authDomain: 'ume-messenger-bd3b1.firebaseapp.com',
  projectId: 'ume-messenger-bd3b1',
  storageBucket: 'ume-messenger-bd3b1.firebasestorage.app',
  messagingSenderId: '62135047180',
  appId: '1:62135047180:web:f34326f4267acf3c89ca29',
  measurementId: 'G-KWRCFTBEXN',
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
    icon: '/icons/Icon-192.png',
    badge: '/icons/Icon-192.png', 
    data: payload.data || {},
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});