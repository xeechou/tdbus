add_library(tdbus
  tdbus.c
  tdbus_array.c
  tdbus_server.c
  tdbus_watcher.c
  tdbus_msg.c
  tdbus_match.c)

target_link_libraries(tdbus PRIVATE dbus-1)

target_include_directories(tdbus PUBLIC ${TDBUS_INCLUDE_DIR})
