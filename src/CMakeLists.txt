add_library(tdbus
  dbus.c dbus_msg.c)

target_link_libraries(tdbus PRIVATE dbus-1)

target_include_directories(tdbus INTERFACE ${CMAKE_CURRENT_LIST_DIR})
