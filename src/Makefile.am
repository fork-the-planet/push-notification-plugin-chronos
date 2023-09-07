AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_PUSH_NOTIFICATION_INCLUDE)

set_lib = lib22_push_notification_chronos_settings.la

lib22_push_notification_chronos_settings_la_LDFLAGS = -module -avoid-version

lib22_push_notification_chronos_settings_la_SOURCES = \
	push-notification-chronos-settings.c

settingsdir = $(dovecot_moduledir)/settings
settings_LTLIBRARIES = $(set_lib)

noinst_HEADERS = \
	push-notification-plugin-chronos.h \
	push-notification-chronos-settings.h

lib22_push_notification_chronos_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib22_push_notification_chronos_plugin.la

lib22_push_notification_chronos_plugin_la_LIBADD = \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)

lib22_push_notification_chronos_plugin_la_DEPENDENCIES = \
	$(LIBDOVECOT_DEPS)

lib22_push_notification_chronos_plugin_la_SOURCES = \
	push-notification-chronos-settings.c \
	push-notification-plugin-chronos.c \
	push-notification-driver-chronos.c

headers =

pkginc_libdir=$(dovecot_pkgincludedir)
pkginc_lib_HEADERS=$(headers)
