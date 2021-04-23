## Tiny DBus library

TDBus library aims to provide an easy to use C API on top of low-level
DBusConnection API. With TDbus, you can easily:

- create a dbus client or server using this library. 
- Sending/reading dbus messsages with one function call.
- Subscribe to signals.
- Adding methods to your dbus service.
- Hook with polling functions to write a nonblocking dbus service.

TDBus does most of the dirty works with a DBus connection when you can focus on
your application.
