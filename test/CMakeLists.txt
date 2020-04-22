include(CTest)

find_program(PROG_DBUS_SEND "dbus-send")
if (NOT PROG_DBUS_SEND)
  message(FATAL_ERROR "dbus-send not found, tests will not work")
endif()

set(TEST_SRCS
  test_tdbus1.c
  test_message.c
  test_service.c
  )

foreach(src ${TEST_SRCS})
  get_filename_component(tgt ${src} NAME_WE)
  add_executable(${tgt}
    ${src})
  target_link_libraries(${tgt}
    PRIVATE tdbus)
  add_test(NAME test_tdbus_${tgt} COMMAND ${tgt})
  list(APPEND TDBUS_TESTS ${tgt})
endforeach()

add_custom_target(check_tdbus
  COMMAND ${CMAKE_CTEST_COMMAND}
  DEPENDS ${TDBUS_TESTS})
