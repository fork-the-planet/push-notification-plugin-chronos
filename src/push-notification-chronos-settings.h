#ifndef PUSH_NOTIFICATION_CHRONOS_SETTINGS_H
#define PUSH_NOTIFICATION_CHRONOS_SETTINGS_H

struct push_notification_chronos_settings {
	pool_t pool;

	const char *url;
	uoff_t msg_max_size;

	/* Generated: */
	struct http_url *parsed_url;
};

extern const struct setting_parser_info push_notification_chronos_setting_parser_info;

#endif
