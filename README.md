# imap-idle-notify
A small programm which listens on an IMAP Mailbox for incoming messages from one or more email address and forward them to Gotify or Ntfy.

### Docker Compose
```
services:
  imap-notify:
    image: ghcr.io/itxworks/imap-idle-notify:latest
    container_name: imap-idle-notify
    env_file:
      - .env
    restart: unless-stopped
    volumes:
      - ./certs:/app/certs:ro    # optional if you have certs
```
`.env`

```
# IMAP server
IMAP_HOST=imap.example.com
IMAP_PORT=993
IMAP_USER=username@example.com
IMAP_PASS=password

# TLS (optional)
IMAP_CA_CERT=
IMAP_CLIENT_CERT=
IMAP_CLIENT_KEY=

# Filters
FROM_FILTER=user@gmail.com,test@example.com
CHECK_FROM=true
CHECK_CC=false
CHECK_BCC=false
CHECK_TO=false

# SKIP Filter
NOTIFY_ALL_EMAILS=false

# Delete Message after processing 
DELETE_AFTER_PROCESSING=false

# Notifier
NOTIFIER_TYPE=gotify# "gotify" or "ntfy"
GOTIFY_URL=https://gotify.example.com
GOTIFY_TOKEN=your-gotify-token
GOTIFY_PRIORITY=10# (0=min, 10=max)
NTFY_URL=https://ntfy.sh
NTFY_TOPIC=emails
NTFY_AUTH_TOKEN=
NTFY_PRIORITY=5#Message priority (1=min, 5=max)

# Timezone
TZ=UTC

# Logging / optional
LOG_LEVEL=info
```
