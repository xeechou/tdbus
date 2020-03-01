add_executable(test_tdbus1
  test_tdbus1.c)

target_link_libraries(test_tdbus1
  tdbus)


add_executable(test_message
  test_message.c)

target_link_libraries(test_message
  PRIVATE tdbus dbus-1
  )
