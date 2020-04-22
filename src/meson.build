tdbus_src = [
  'tdbus.c',
  'tdbus_array.c',
  'tdbus_server.c',
  'tdbus_watcher.c',
  'tdbus_msg.c',
  'tdbus_match.c',
]

lib_tdbus = static_library(
  'tdbus',
  tdbus_src,
  c_args : global_args,
  include_directories : include_tdbus,
  dependencies: dep_dbus,
)

dep_tdbus = declare_dependency(
  link_with : lib_tdbus,
  include_directories : include_tdbus,
  compile_args : global_args,
)
