project('tdbus', 'c',
	version : '0.1',
	default_options: [
	  'warning_level=3',
	  'c_std=gnu11',
	  'werror=true'
	],
	license: 'GPLv2.1+')

# adding options
cc = meson.get_compiler('c')

global_args_maybe = [
	'-Wno-unused-parameter',
	'-Wno-missing-field-initializers',
	'-Wno-pedantic',

]
global_args = []

foreach a : global_args_maybe
  if cc.has_argument(a)
    global_args += a
  endif
endforeach

if get_option('buildtype') == 'release' and cc.has_argument(a)
  global_args += '-fvisibility=hidden' #this options hides most
endif

dep_dbus = dependency('dbus-1', version: '>= 1.6', required: true)
if not dep_dbus.found()
  error('dbus-1 >= 1.6 not found')
endif

include_tdbus = include_directories('include')

subdir('src')
subdir('test')
