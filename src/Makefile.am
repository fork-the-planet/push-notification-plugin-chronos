AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_PUSH_NOTIFICATION_INCLUDE)

chronos_push_notification_plugin_sources =

lib22_chronos_push_notification_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib22_chronos_push_notification_plugin.la

lib22_chronos_push_notification_plugin_la_LIBADD = \
	$(LIBDOVECOT)

lib22_chronos_push_notification_plugin_la_DEPENDENCIES = \
	$(LIBDOVECOT_DEPS)

lib22_chronos_push_notification_plugin_la_SOURCES = \
	$(chronos_push_notification_plugin_sources)

settingsdir = $(dovecot_moduledir)/settings
settings_LTLIBRARIES = $(set_lib)

headers =

pkginc_libdir=$(dovecot_pkgincludedir)
pkginc_lib_HEADERS=$(headers)
