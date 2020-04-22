test_tdbus1 = executable(
  'test_tdbus1',
  'test_tdbus1.c',
  dependencies : dep_tdbus)

test('test_tdbus1', test_tdbus1)

test_tdbus_message = executable(
  'test_message',
  'test_message.c',
  dependencies : dep_tdbus)

test('test_tdbus_message', test_tdbus_message)

test_tdbus_service = executable(
  'test_tdbus_service',
  'test_service.c',
  dependencies : dep_tdbus)

find_program('dbus-send')
test('test_service', test_tdbus_service)
