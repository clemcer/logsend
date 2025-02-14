
# Config Walkthr

## 📁 Basic Structure

The `config.yaml` file is divided into four main sections:
1. **ntfy configuration**: set your ntfy url, topic, token, priority and tags
2. **`containers`**: Define which containers to monitor and their specific keywords.
3. **`global_keywords`**: Keywords that apply to **all** monitored containers.
4. **`settings`**: Global settings like cooldowns and log levels.

---

## `ntfy` section

In this section, you can configure your ntfy settings. The `url` and `token` are required parameters. The `tags`, `topic`, and `priority` have default values and can be defined globally in this section or individually for each container.

```yaml
ntfy:
  url: "http://192.168.178.184:8080"   # URL of your ntfy instance
  topic: "loggifly"                   # Default topic for notifications (overridden by container-specific topics)
  token: "your_token"
  tags: warning                       # Default tag (overridden by container-specific tags)
  priority: 3 # Default valuw
```
---

## 🐳 `containers` Section

This section defines the containers you want to monitor and the keywords/regex patterns to look for.
You can also set the topic, tags and priority for your ntfy notification which will be used over the global configuration

### Example:
```yaml
containers:
  hrconvert2:
    keywords_with_attachment:
      - regex: "\\bhttp\\b"  # Case-insensitive regex for "HTTP"
      - "error"              # Plain-text keyword
  nextcloud-app-1:
    keywords_with_attachment:
      - regex: "\\b(unauthorized|permission denied)\\b"
      - "disk full"
```
### Key Details:

- Container Name: Use the exact name of the Docker container (e.g., hrconvert2).
- keywords_with_attachment:
  - A list of keywords or regex patterns to monitor.
  - If a match is found, the last 50 lines of the log are attached to the notification.
  - Use regex: for regex patterns (e.g., "\\bhttp\\b").
  - Use plain strings for exact matches (e.g., "error").

 ---
 
## 🌍 `global_keywords` Section
Keywords defined here apply to all containers being monitored.
### Example:

```yaml

global_keywords:
  - regex: "\\b(critical|panic)\\b"  # Match "critical" or "panic" in any container
  - "out of memory"                  # Plain-text keyword
```

### Key Details:
- Global Scope: These keywords are checked in all containers.
- Same Syntax: Use regex: for patterns or plain strings for exact matches.

---

## ⚙️ `settings` Section

This section defines global behavior for Loggifly.

### Example:

```yaml
settings:
  keyword_notification_cooldown: 5  # Cooldown (in seconds) between notifications per keyword
  log_level: "INFO"                 # Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
```

### Key Details:

- keyword_notification_cooldown:
  - Prevents spam by limiting how often a notification is sent for the same keyword. Default: 5 seconds.
- log_level:
  - Set Log Level. Default: INFO

---

## Enviroment Variables

These are the global settings you can set via docker environment variables in either your docker compose or .env file

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| **NTFY_URL**                      | URL of the ntfy notification service.                    | _N/A_    |
| **NTFY_TOKEN**                    | Authentication token for ntfy.                           | _N/A_    |
| **NTFY_TOPIC**                    | Notification topic for ntfy.                             | _N/A_  |
| **NTFY_TAGS**                     | Ntfy [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications.                 | warning  |
| **NTFY_PRIORITY**                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| **NOTIFICATION_COOLDOWN**         | Cooldown period (in seconds) per container per keyword<br> before a new message can be sent  | 5        |
| **LOG_LEVEL**                     | Log Level for Loggifly container logs.                    | INFO     |
| **ATTACHMENT_LINES**              | Define the number of Log Lines in the attachment file     | False     |
| **DISABLE_RESTART**               | Disable automatic restarts when the config file is changed.| False     |
| **DISBLE_START_MESSAGE**          | Disable startup message.                                  | False     |
| **DISBLE_SHUTDOWN_MESSAGE**       | Disable shutdown message.                                 | False     |
| **DISABLE_RESTART_MESSAGE**       | Disable message on config change when programm restarts.| False     |
| **MULTI_LINE_ENTRIES**            | When enabled the programm tries to catch entries that span multiple log lines.<br>If you encounter bugs or you simply don't need it you can disable it.| False     |




---

## 📃 Full example config.yaml
This is how a config file could look like. Keep in mind that this is just an example how a config.yaml could be structured and some keywords might not even make sense for some containers.

```yaml
containers:
  audiobookshelf:
    ntfy_topic: media
    ntfy_tags: "books, headphones"     
    keywords:
      - "requested download"
      - "downloaded item"
      - "user"
      - "login"
      - regex: 'download (failed|error)'    # Matches "download failed" or "download error"
        
  crowdsec:
    ntfy_topic: security
    ntfy_tags: "shield, rotating_light"  
    keywords:
      - "blocked"

  vaultwarden:
    ntfy_topic: security
    ntfy_tags: "lock, key"   
    keywords:
      - "login"
      - "incorrect"
      - "username"
      - "password"

  syncthing:
    ntfy_tags: "arrows_counterclockwise, recycle" 
    keywords:
      - "sync error"
      - "failed to connect"
    keywords_with_attachment:
      - regex: 'fatal'                     
global_keywords:
  keywords_with_attachment:
    - regex: "\\b(critical|panic)\\b"
    - "error"
    - "segfault"
    - "panic"
    - "fatal"
    - "failed login"

ntfy:
  url: "http://192.168.178.184:82"   # URL of your ntfy instance
  topic: "Loggifly"                   # Default topic for notifications (overridden by container-specific topics)
  token: "token"                     # Authentication token (if required)
  tags: "warning"

settings:
  keyword_notification_cooldown: 10
  log_level: "INFO"
```