/* Copyright (c) 2022 Dovect Authors, see the included LICENSE file */

#include "lib.h"

#include "push-notification-drivers.h"
#include "push-notification-plugin-chronos.h"

/* Plugin interface */

const char *push_notification_chronos_plugin_version = DOVECOT_ABI_VERSION;
const char *push_notification_chronos_plugin_dependencies[] =
	{ "push_notification", NULL };

extern struct push_notification_driver push_notification_driver_chronos;

void push_notification_chronos_plugin_init(struct module *module ATTR_UNUSED) {
	push_notification_driver_register(&push_notification_driver_chronos);
}

void push_notification_chronos_plugin_deinit(void) {
	push_notification_driver_unregister(&push_notification_driver_chronos);
}
