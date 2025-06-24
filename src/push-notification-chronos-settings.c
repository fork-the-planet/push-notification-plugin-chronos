/* Copyright (c) 2023 Dovect Authors, see the included LICENSE file */

#include "lib.h"
#include "http-url.h"
#include "settings.h"
#include "settings-parser.h"

#include "push-notification-chronos-settings.h"

#define DEFAULT_MSG_MAX_SIZE (1 * 1024 * 1024)

static bool push_notification_chronos_settings_check(void *, pool_t, const char **);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("push_notification_chronos_"#name, name, struct push_notification_chronos_settings)

static const struct setting_define push_notification_chronos_setting_defines[] = {
	DEF(STR, url),
	DEF(SIZE, msg_max_size),

	SETTING_DEFINE_LIST_END,
};

static const struct push_notification_chronos_settings push_notification_chronos_default_settings = {
	.url = "",
	.msg_max_size = DEFAULT_MSG_MAX_SIZE,
};

const struct setting_parser_info push_notification_chronos_setting_parser_info = {
	.name = "push_notification_chronos",

	.defines = push_notification_chronos_setting_defines,
	.defaults = &push_notification_chronos_default_settings,

	.struct_size = sizeof(struct push_notification_chronos_settings),
	.pool_offset1 = 1 + offsetof(struct push_notification_chronos_settings, pool),
	.check_func = push_notification_chronos_settings_check,
};

const struct setting_parser_info *push_notification_chronos_settings_set_infos[] = {
	&push_notification_chronos_setting_parser_info,
	NULL,
};

const char *push_notification_chronos_settings_version = DOVECOT_ABI_VERSION;

static bool
push_notification_chronos_settings_check(void *_set, pool_t pool,
					 const char **error_r)
{
	struct push_notification_chronos_settings *set = _set;
	const char *error;

	if (set->url[0] != '\0') {
		if (http_url_parse(set->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
				   pool, &set->parsed_url, &error) < 0) {
			*error_r = t_strdup_printf(
				"Invalid push_notification_chronos_url '%s': %s",
				set->url, error);
			return FALSE;
		}
	} else
		set->parsed_url = NULL;

	if (set->msg_max_size == 0) {
		*error_r = "push_notification_chronos_msg_max_size must not be 0";
		return FALSE;
	}

	return TRUE;
}
