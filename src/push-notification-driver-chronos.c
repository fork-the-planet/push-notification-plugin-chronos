/* Copyright (c) 2022 Dovect Authors, see the included LICENSE file */

#include "lib.h"
#include "hash.h"
#include "http-client.h"
#include "http-url.h"
#include "imap-bodystructure.h"
#include "ioloop.h"
#include "iostream-ssl.h"
#include "istream.h"
#include "json-ostream.h"
#include "mail-storage-private.h"
#include "message-part-data.h"
#include "message-size.h"
#include "push-notification-drivers.h"
#include "push-notification-event-messagenew.h"
#include "push-notification-events.h"
#include "push-notification-plugin.h"
#include "push-notification-settings.h"
#include "push-notification-txn-msg.h"
#include "settings.h"
#include "str-parse.h"
#include "str.h"

#include "push-notification-chronos-settings.h"

/* Default values. */
static const char *const default_events[] = { "MessageNew", NULL };

/* Calendar invite search parameters. */
#define CHRONOS_PN_ICAL_MIME_TYPE "text"
#define CHRONOS_PN_ICAL_MIME_SUBTYPE "calendar"
#define CHRONOS_PN_ICAL_ATC_SUFFIX "ics"

#define CHRONOS_PN_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, push_notification_chronos_user_module)
#define CHRONOS_PN_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, push_notification_chronos_user_module)

struct push_notification_driver_chronos_user {
	union mail_user_module_context module_ctx;

	HASH_TABLE(const char *, void *) dedup_table;
};

static MODULE_CONTEXT_DEFINE_INIT(push_notification_chronos_user_module,
				  &mail_user_module_register);

struct push_notification_driver_chronos_global {
	struct http_client *http_client;
	int refcount;
};

static struct push_notification_driver_chronos_global *chronos_global = NULL;

struct push_notification_driver_chronos_http_ctx {
	pool_t pool;
	string_t *json;
	struct event *event;
	struct istream *payload;
};

struct push_notification_driver_chronos_config {
	struct push_notification_driver_chronos_http_ctx *http_ctx;
	struct event *event;
	struct http_url *http_url;
	struct mail_user *user;
	uoff_t msg_max_size;
};

static void
push_notification_driver_chronos_init_chronos_user(struct mail_user *user)
{
	struct push_notification_driver_chronos_user *chronos_user =
		CHRONOS_PN_USER_CONTEXT(user);

	chronos_user =
		p_new(user->pool, struct push_notification_driver_chronos_user, 1);
	hash_table_create(&chronos_user->dedup_table,
			  user->pool, 0, str_hash, strcmp);
	MODULE_CONTEXT_SET(user, push_notification_chronos_user_module,
			   chronos_user);
}

static void
push_notification_driver_chronos_chronos_user_deinit(struct mail_user *user)
{
	struct push_notification_driver_chronos_user *chronos_user =
		CHRONOS_PN_USER_CONTEXT_REQUIRE(user);
	hash_table_destroy(&chronos_user->dedup_table);
}

static bool
push_notification_driver_chronos_init_global(struct mail_user *user,
					     const char *name)
{
	const char *error;
	chronos_global = i_new(struct push_notification_driver_chronos_global, 1);

	struct event *event = event_create(user->event);
	char *filter_name = p_strdup_printf(
			event_get_pool(event), "%s/%s",
			PUSH_NOTIFICATION_SETTINGS_FILTER_NAME,
			settings_section_escape(name));
	event_set_ptr(event, SETTINGS_EVENT_FILTER_NAME, filter_name);

	if (http_client_init_auto(event, &chronos_global->http_client,
				  &error) < 0) {
		e_error(user->event, "Unable to initialize the HTTP client: %s",
			error);
		event_unref(&event);
		return FALSE;
	}
	event_unref(&event);

	chronos_global->refcount = 1;

	return TRUE;
}

static void
push_notification_driver_chronos_global_unref(void)
{
	if (chronos_global != NULL) {
		if (chronos_global->http_client != NULL)
			http_client_wait(chronos_global->http_client);
		i_assert(chronos_global->refcount > 0);
		--chronos_global->refcount;

		if (chronos_global->refcount <= 0) {
			if (chronos_global->http_client != NULL)
				http_client_deinit(&chronos_global->http_client);
			i_free(chronos_global);
		}
	}
}

static int
push_notification_driver_chronos_init(
		struct mail_user *user, pool_t pool, const char *name,
		void **context, const char **error_r)
{
	push_notification_driver_chronos_init_chronos_user(user);

	struct push_notification_chronos_settings *chronos_settings;
	if (settings_get_filter(user->event, PUSH_NOTIFICATION_SETTINGS_FILTER_NAME,
				name, &push_notification_chronos_setting_parser_info,
				0, &chronos_settings, error_r) < 0)
		return -1;

	struct push_notification_driver_chronos_config *dconfig;
	dconfig = p_new(pool, struct push_notification_driver_chronos_config, 1);
	dconfig->user = user;
	dconfig->event = event_create(user->event);
	event_add_category(dconfig->event, push_notification_get_event_category());
	event_set_append_log_prefix(dconfig->event, "push-notification-chronos: ");

        /* The settings check is deliberately only validating a url if it is
           given in the settings. Otherwise any file that does not contain
           push-notification specific settings would fail the validation.
	   Thus we need to check here, whether the parsed url exists. */
        if (chronos_settings->parsed_url == NULL) {
		*error_r = "push_notification_chronos_url is missing or empty";
		event_unref(&dconfig->event);
		settings_free(chronos_settings);
		return -1;
	}

	dconfig->http_url = http_url_clone_with_userinfo(
			pool, chronos_settings->parsed_url);
	dconfig->msg_max_size = chronos_settings->msg_max_size;
	e_debug(dconfig->event,
		"Using config: url=%s, msg max size = %"PRIuUOFF_T"B",
		http_url_create(dconfig->http_url), dconfig->msg_max_size);

	settings_free(chronos_settings);

	if (chronos_global == NULL) {
		if (!push_notification_driver_chronos_init_global(user, name)) {
			event_unref(&dconfig->event);
			return -1;
		}
	} else {
		i_assert(chronos_global->refcount > 0);
		++chronos_global->refcount;
	}

	*context = dconfig;

	return 0;
}

static bool
push_notification_driver_chronos_begin_txn(
	struct push_notification_driver_txn *dtxn)
{
	struct push_notification_driver_chronos_config *dconfig =
		dtxn->duser->context;

	time_t expire = INT_MAX;
	if (expire < ioloop_time) {
		e_debug(dconfig->event, "Skipped due to expiration (%ld < %ld)",
			(long)expire, (long)ioloop_time);
		return FALSE;
	}

	const char *const *events = default_events;
	for (; *events != NULL; events++) {
		if (strcmp(*events, "MessageNew") == 0) {
			e_debug(dconfig->event, "Handling %s event", *events);

			/* The push notification chronos plugin is not directly
			   accessing any data from the messagenew event, as the
			   full body needs to be checked for a calendar invite.
			   Unfortunately not setting any flags would prevent a
			   messagenew-event from being properly initialized.
			   Hence set an arbitrary flag to enable the process_msg
			   callback from receiving viable data.

			   See push_notification_event_messagenew_event() in
			   the dovecot core project. */
			struct push_notification_event_messagenew_config *config =
				p_new(dtxn->ptxn->pool,
				      struct push_notification_event_messagenew_config,
				      1);
			config->flags = PUSH_NOTIFICATION_MESSAGE_HDR_FROM;
			push_notification_event_init(dtxn, *events, config,
						     dconfig->event);
		}
	}

	return TRUE;
}

static bool
push_notification_driver_chronos_ical_search_part(
	const struct message_part_data *data)
{
	/* Check #1: Look for text/calendar parts. */
	if (data->content_type != NULL && data->content_subtype != NULL &&
	    (strcasecmp(data->content_type, CHRONOS_PN_ICAL_MIME_TYPE) == 0) &&
	    (strcasecmp(data->content_subtype, CHRONOS_PN_ICAL_MIME_SUBTYPE) == 0))
		return TRUE;

	/* Check #2: Look for ".ics" suffix in attachment filenames. */
	const char *ext;
	for (unsigned int i = 0; i < data->content_disposition_params_count; i++) {
		const struct message_part_param *param =
			&data->content_disposition_params[i];

		if (param->name != NULL &&
		    strcasecmp(param->name, "filename") == 0 &&
		    param->value != NULL) {
			if (((ext = strrchr(param->value, '.')) != NULL) &&
			    (strcasecmp(ext + 1, CHRONOS_PN_ICAL_ATC_SUFFIX) == 0))
				return TRUE;
		}
	}

	return FALSE;
}

static bool
push_notification_driver_chronos_ical_search_allparts(
	const struct message_part *initial_part)
{
	ARRAY(struct message_part) parts;
	t_array_init(&parts, 1);
	array_push_back(&parts, initial_part);

	while (array_count(&parts) > 0) {
		const struct message_part *part = array_front(&parts);

		if (part->data != NULL &&
		    push_notification_driver_chronos_ical_search_part(part->data))
			return TRUE;
		if (part->next != NULL)
			array_push_back(&parts, part->next);
		if (part->children != NULL)
			array_push_back(&parts, part->children);

		array_pop_front(&parts);
	}
	return FALSE;
}

static bool
push_notification_driver_chronos_ical_search(
	struct push_notification_driver_chronos_config *dconfig,
	struct mail *mail)
{
	struct message_part *all_parts;
	if (mail_get_parts(mail, &all_parts) < 0)
		return FALSE;

	const char *bodystructure;
	if ((all_parts->data == NULL) &&
	    (mail_get_special(mail, MAIL_FETCH_IMAP_BODYSTRUCTURE,
			      &bodystructure) < 0))
		return FALSE;

	const char *error;
	pool_t bodystructure_parse_pool = pool_alloconly_create(
		"chronos bodystructure parse", 512);
	if ((all_parts->data == NULL) &&
	    (imap_bodystructure_parse(bodystructure, bodystructure_parse_pool,
				      all_parts, &error) < 0)) {
		e_error(dconfig->event, "%s", error);
		return FALSE;
	}

	/* Parts now have bodystructure information populated. This info is
	 * contained in each part's context struct member. */
	bool has_ical = push_notification_driver_chronos_ical_search_allparts(all_parts);
	pool_unref(&bodystructure_parse_pool);
	return has_ical;
}

static void
push_notification_driver_chronos_handle_mail_error(
	struct push_notification_driver_chronos_config *dconfig,
	struct mail *mail, uint32_t mail_uid, const char *prefix)
{
	enum mail_error error;
	const char *errstr = mail_get_last_internal_error(mail, &error);

	if (error == MAIL_ERROR_EXPUNGED)
		e_info(dconfig->event, "%s UID=%u: %s", prefix, mail_uid, errstr);
	else
		e_error(dconfig->event, "%s UID=%u: %s", prefix, mail_uid, errstr);
}

static bool
push_notification_driver_chronos_read_mail_body(
	struct mailbox_transaction_context *t,
	struct push_notification_driver_chronos_config *dconfig,
	uint32_t mail_uid, string_t **body)
{
	struct mail *mail = mail_alloc(t, MAIL_FETCH_STREAM_BODY, NULL);
	if (!mail_set_uid(mail, mail_uid)) {
		push_notification_driver_chronos_handle_mail_error(
			dconfig, mail, mail_uid,
			"Unable to fetch email with uid");
		mail_free(&mail);
		return FALSE;
	}

	/* Try to deduplicate messages by Message-ID header if it exists. */
	struct push_notification_driver_chronos_user *chronos_user =
		CHRONOS_PN_USER_CONTEXT_REQUIRE(dconfig->user);
	const char *key;
	if (mail_get_first_header(mail, "Message-ID", &key) < 0) {
		push_notification_driver_chronos_handle_mail_error(
			dconfig, mail, mail_uid,
			"Unable to lookup Message-ID header field for uid");
	} else if (key != NULL && *key != '\0') {
		if (hash_table_lookup(chronos_user->dedup_table, key) != NULL) {
			e_debug(dconfig->event,
				"Message UID %u Message-ID %s is a duplicate - not sending push notification",
				mail_uid, key);
			mail_free(&mail);
			return FALSE;
		} else {
			e_debug(dconfig->event,
				"Message UID %u Message-ID %s is not a duplicate",
				mail_uid, key);
			key = p_strdup(dconfig->user->pool, key);
			hash_table_insert(chronos_user->dedup_table,
					  key, POINTER_CAST(1));
		}
	}

	/* Make sure email contains relevant calendar data. */
	if (!push_notification_driver_chronos_ical_search(dconfig, mail)) {
		e_debug(dconfig->event, "Mail does not contain calendar invite");
		mail_free(&mail);
		return FALSE;
	}

	/* get body via stream */
	struct istream *input;
	struct message_size hdr_size, body_size;
	if (mail_get_stream(mail, &hdr_size, &body_size, &input) < 0) {
		push_notification_driver_chronos_handle_mail_error(
			dconfig, mail, mail_uid,
			"Unable to get mail stream for uid");
		mail_free(&mail);
		return FALSE;
	}

	/* Check message body size against configured max size. */
	uoff_t full_size = hdr_size.physical_size + body_size.physical_size;
	if (full_size > dconfig->msg_max_size) {
		e_debug(dconfig->event,
			"Mail exceeds configured max size. "
			"Mail: %"PRIuUOFF_T"B vs. Max Size: %"PRIuUOFF_T"B",
			full_size, dconfig->msg_max_size);
		mail_free(&mail);
		return FALSE;
	}

	/* append data from stream to body str_t */
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		size_t body_len = str_len(*body);
		if (body_len < dconfig->msg_max_size) {
			size_t max_size = I_MIN(size, dconfig->msg_max_size - body_len);
			str_append_data(*body, data, max_size);
			i_stream_skip(input, max_size);
		} else
			break;
	}
	/* This assertion might trigger if there was more data read, than
	   initially anticipated. */
	i_assert(ret == -1);

	if (input->stream_errno != 0) {
		e_error(dconfig->event, "read(%s) failed: %s",
			i_stream_get_name(input),
			i_stream_get_error(input));
		mail_free(&mail);
		return FALSE;
	}

	mail_free(&mail);
	return TRUE;
}

static void
push_notification_driver_chronos_http_callback(
	const struct http_response *response,
	struct push_notification_driver_chronos_http_ctx *ctx)
{
	switch (response->status / 100) {
	case 2:
		/* Success */
		e_debug(ctx->event, "Notification sent successfully: %s",
			http_response_get_message(response));
		break;

	default:
		/* Error */
		e_error(ctx->event, "Error when sending notification: %s",
			http_response_get_message(response));
		break;
	}

	/* Cleanup */
	i_stream_unref(&ctx->payload);
	str_free(&ctx->json);
	event_unref(&ctx->event);
	pool_unref(&ctx->pool);
}

static void
push_notification_driver_chronos_process_msg(
	struct push_notification_driver_txn *dtxn,
	struct push_notification_txn_msg *msg)
{
	struct push_notification_driver_chronos_config *dconfig =
		dtxn->duser->context;

	/* Only push message on "MessageNew" events. */
	struct push_notification_event_messagenew_data *message_new =
		push_notification_txn_msg_get_eventdata(msg, "MessageNew");
	if (message_new == NULL)
		return;

	/* Open and sync new instance of the mailbox to get most recent
	   status/data. */
	struct mailbox *mbox = mailbox_alloc(
			mailbox_get_namespace(dtxn->ptxn->mbox)->list,
			mailbox_get_vname(dtxn->ptxn->mbox), MAILBOX_FLAG_READONLY);
	if (mailbox_sync(mbox, 0) < 0) {
		e_error(dconfig->event, "mailbox_sync(%s) failed: %s",
			mailbox_get_vname(dtxn->ptxn->mbox),
			mailbox_get_last_internal_error(mbox, NULL));
	}

	pool_t http_ctx_pool = pool_alloconly_create("chronos http context", 512);
	struct mailbox_transaction_context *t = mailbox_transaction_begin(
		mbox, 0, __func__);
	string_t *body = str_new(http_ctx_pool, dconfig->msg_max_size);
	if (!push_notification_driver_chronos_read_mail_body(t, dconfig,
							     msg->uid, &body)) {
		(void)mailbox_transaction_commit(&t);
		mailbox_free(&mbox);
		pool_unref(&http_ctx_pool);
		return;
	}

	(void)mailbox_transaction_commit(&t);
	mailbox_free(&mbox);

	/* Setup context for http request. This is done to split http resources
	   from the main handling of the push notification message resources,
	   that are done in a synchronous manner. */
	struct push_notification_driver_chronos_http_ctx *ctx = p_new(
		http_ctx_pool, struct push_notification_driver_chronos_http_ctx, 1);
	ctx->pool = http_ctx_pool;
	ctx->event = event_create(dconfig->event);
	event_add_category(ctx->event, push_notification_get_event_category());
	event_set_append_log_prefix(ctx->event, "http callback: ");

	/* Setup http request. */
	struct http_client_request *http_req = http_client_request_url(
		chronos_global->http_client, "PUT", dconfig->http_url,
		push_notification_driver_chronos_http_callback, ctx);
	http_client_request_set_event(http_req, dtxn->ptxn->event);
	http_client_request_add_header(http_req, "Content-Type",
				       "application/json; charset=utf-8");

	/* Create json payload to send. */
	struct json_ostream *json_output;
	ctx->json = str_new(ctx->pool, dconfig->msg_max_size);
	json_output = json_ostream_create_str(ctx->json, 0);
	json_ostream_ndescend_object(json_output, NULL);
	json_ostream_nwrite_string(json_output, "user",
				   dtxn->ptxn->muser->username);
	json_ostream_nwrite_string(json_output, "folder", msg->mailbox);
	json_ostream_nwrite_string(json_output, "event", "messageNew");
	json_ostream_nwrite_string(json_output, "body", str_c(body));
	json_ostream_nascend_object(json_output);
	json_ostream_nfinish_destroy(&json_output);

	/* Set payload to http request and press send. */
	ctx->payload = i_stream_create_from_data(str_data(ctx->json),
						 str_len(ctx->json));
	http_client_request_set_payload(http_req, ctx->payload, FALSE);
	http_client_request_submit(http_req);
}

static void
push_notification_driver_chronos_deinit(
	struct push_notification_driver_user *duser)
{
	struct push_notification_driver_chronos_config *dconfig = duser->context;
	event_unref(&dconfig->event);

	push_notification_driver_chronos_chronos_user_deinit(dconfig->user);
	push_notification_driver_chronos_global_unref();
}

static void
push_notification_driver_chronos_cleanup(void)
{
	push_notification_driver_chronos_global_unref();
}

/* Driver definition */

extern struct push_notification_driver push_notification_driver_chronos;

struct push_notification_driver push_notification_driver_chronos = {
	.name = "chronos",
	.v = {
		.init = push_notification_driver_chronos_init,
		.begin_txn = push_notification_driver_chronos_begin_txn,
		.process_msg = push_notification_driver_chronos_process_msg,
		.deinit = push_notification_driver_chronos_deinit,
		.cleanup = push_notification_driver_chronos_cleanup,
	},
};
