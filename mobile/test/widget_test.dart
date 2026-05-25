import 'package:flutter_test/flutter_test.dart';
import 'package:private_messenger_mvp/app.dart';

void main() {
  testWidgets('App starts', (WidgetTester tester) async {
    await tester.pumpWidget(const MessengerApp());

    expect(find.text('Вход'), findsOneWidget);
  });
}