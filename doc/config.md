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

#### `push_notification_chronos_url`

Required.

HTTP URL endpoint to send formatted push notification payload to.

#### `push_notification_chronos_msg_max_size`

Default: `1mb`.

Size of message at which it is considered too large for being send as a push
notification.

### Example configuration

```
push_notification chronos {
  driver = chronos
  push_notification_chronos_url = http://login:pass@node1.domain.tld:8009/preliminary/http-notify/v1/notify
  push_notification_chronos_msg_max_size = 500kb
}
```
