# Chronos Push Notification Plugin Configuration

This plugin allows you to send push notification to an endpoint of your choice
whenever emails with calendar invitations are received.

You need to enable the `push_notification_chronos` plugin. Additionally the
`notify` and `push_notification` plugins are required to enable general push
notification support.

```
mail_plugins = $mail_plugins notify push_notification push_notification_chronos
```

## Configuration

### Available configuration options

#### `url`

Required.

HTTP URL endpoint to send formatted push notification payload to.

#### `max_retries`

Default: `1`.

Number of HTTP retries in case of timeouts.

#### `timeout`

Default: `2s`.

Duration an HTTP request can take before being considered timed out.

#### `msg_max_size`

Default: `1mb`.

Size of message at which it is considered too large for being send as a push
notification.

### Example configuration

```
plugin {
  push_notification_driver = chronos:url=http://login:pass@node1.domain.tld:8009/preliminary/http-notify/v1/notify max_retries=2 timeout=2500ms msg_max_size=500kb
}
```
