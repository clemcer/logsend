<a name="readme-top"></a>

<br />
<div align="center">
  <a href="clemcer/loggifly">
    <img src="/images/icon.png" alt="Logo" width="200" height="auto">
  </a>

<h1 align="center">LoggiFly</h1>

  <p align="center">
    <a href="https://github.com/clemcer/loggifly/issues">Report Bug</a>
    ·
    <a href="https://github.com/clemcer/loggifly/issues">Request Feature</a>
  </p>
</div>

<br>

**LoggiFly** - A Lightweight Tool to monitor Docker Logs and send Notifications. <br>
Never miss critical container events again - Get instant alerts for security breaches, system errors, or custom patterns through your favorite notification channels. 🚀

<div align="left">
   <img src="/images/vault_failed_login.gif" alt="Failed Vaultwarden Login" width="300" height="auto">
</div>


**Ideal For**:
- ✅ Catching security breaches (e.g., failed logins in Vaultwarden)
- ✅ Debugging crashes with attached log context
- ✅ Monitoring custom app behaviors (e.g., when a user downloads an audiobook on your Audiobookshelf server)
---

## Content

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Quick Start](#️-quick-start)
- [Configuration Deep Dive](#-Configuration-Deep-Dive)
- [Tips](#-tips)

---

## 🚀 Features

- **🔍 Plain Text, Regex & Multi-Line Log Detection**: Catch simple keywords or complex patterns in log entries that span multiple lines.
- **🚨 Ntfy/Apprise Alerts**: Send notifications directly to Ntfy or via Apprise to 100+ different services (Slack, Discord, Telegram).
- **🐳 Fine-Grained Control**: Unique keywords and other settings (like ntfy topic/tags/priority) per container.
- **📁 Log Attachments**: Automatically include a log file to the notification for context.
- **⚡ Auto-Restart on Config Change**: The program restarts when it detects that the config file has been changed.

---
## 🖼 Screenshots

<div align="center">
   <img src="/images/abs_login.png" alt="Audiobookshelf Login" width="300" height="auto">
   <img src="/images/vault_failed_login.png" alt="Vaultwarden Login" width="300" height="auto">
   <img src="/images/abs_download.png" alt="Audiobookshelf Download" width="300" height="auto">
  <img src="/images/ebook2audiobook.png" alt="Ebook2Audiobook conversion finished" width="300" height="auto">

</div>

---

## ⚡️ Quick start
You have two options. There is a simple way to run this with just docker environment variables and a more flexible way with a config.yaml file which lets you set different keywords and settings per container and use complex regex patterns.


<details><summary><em>Click to expand:</em> 🐋 <strong>1. Option: Docker Compose only</strong></summary>d.

```yaml
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:  
    # Configure either Ntfy or Apprise or both
      NTFY_URL:
      NTFY_TOPIC: 
      NTFY_TOKEN:                            # In case you need authentication
      APPRISE_URL:                           # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
      CONTAINERS:                            # comma separated list, e.g., vaultwarden,audiobookshelf
      GLOBAL_KEYWORDS:                       # comma separated list, e.g., login,error
      # When one of these keywords is found a log file will be attached to the notification
      GLOBAL_KEYWORDS_WITH_ATTACHMENT:       #comma separated list, e.g., critical,warning 
```
</details>


<details><summary><em>Click to expand:</em><strong> 📃 2. Option: Set up a config.yaml for more fine-grained control</strong></summary><br>
  
1) Insert the following line in the volumes section of the docker compose from Option 1:
```yaml
      - ./loggifly/config.yaml:/app/config.yaml # set the path of your config file on the left side of the mapping
```

<br>

2) Configure your config.yaml.

```yaml
# You have to configure at least one container.
containers:
  container-name:  # Exact container name
  # You don't have to use both `keywords` and `keyword_with_attachment`. One is enough
    keywords:
      - error
      - regex: (username|password).*incorrect  # Use regex patterns when you need them
    # Attach a log file to the notification 
    keywords_with_attachment:
      - warn

# Optional. These keywords are being monitored for all configured containers
global_keywords:
  keywords:
    - failed
  keywords_with_attachment:
    - critical

notifications:     
  # Configure either Ntfy or Apprise or both
  ntfy:
    url: http://your-ntfy-server  
    topic: loggifly                   
    token: ntfy-token               # In case you need authentication
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)```    
```
</details><br>

**When everything is configured start the container**
```bash
docker compose up -d
```

---


## 🤿 Configuration Deep Dive
The Quick Start only covered the essential settings, here is a more detailed walktrough of the configuration options.

### 📁 Basic Structure

The `config.yaml` file is divided into four main sections:

1. **`settings`**: Global settings like cooldowns and log levels.
2. **`notifications`**: Configure Ntfy (URL, Topic, Token, Priority and Tags) and/or your Apprise URL
3. **`containers`**: Define which Containers to monitor and their specific Keywords.
4. **`global_keywords`**: Keywords that apply to **all** monitored Containers.

<details><summary><em>Click to expand:</em><strong> ⚙️ Settings </strong></summary>

```yaml
# These are the default settings
settings:          
  log_level: INFO               # DEBUG, INFO, WARNING, ERROR
  notification_cooldown: 5      # Seconds between alerts for same keyword (per container)
  attachment_lines: 20          # Number of Lines to include in log attachments
  multi_line_entries: true      # Detect multi-line log entries
  disable_restart: false        # Disable restart when a config change is detected 
  disable_start_message: false  # Suppress startup notification
  disable_shutdown_message: false  # Suppress shutdown notification
  disable_restart_message: false   # Suppress config reload notification
```

</details>



<details><summary><em>Click to expand:</em><strong> 📭 notifications </strong></summary>

```yaml
notifications:                       
  # At least one of the two (Ntfy/Apprise) is required.
  ntfy:
    url: http://your-ntfy-server    # Required. The URL of your Ntfy instance
    topic: loggifly.                # Required. the topic for Ntfy
    token: ntfy-token               # In case you need authentication 
    priority: 3                     # Ntfy priority (1-5)
    tags: kite,mag                  # Ntfy tags/emojis 
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
```
</details>


<details><summary><em>Click to expand:</em><strong> 🐳 containers </strong></summary>

```yaml
containers:
  container-name:               # Must match exact container_name
    ntfy_topic: your_topic      # Overrides global ntfy topic for this contaner.
    ntfy_tags: "tag1, tag2"     # Overrides global ntfy tags for this contaner.
    ntfy_priority: 4            # Overrides global ntfy priority for this contaner. (1-5)
    attachment_lines: 10        # overrides the global number of lines included in the attachments for this container
    notification_cooldown: 10   # overrides the global cooldown per keyword for this container

  # You don't have to use both `keywords` and `keyword_with_attachment`. One is enough. 
    keywords:                                 
      - error                                  # Simple text matches
      - regex: (username|password).*incorrect  # Use regex patterns when you need them
    # When one of these keywords is found a logfile is attached to the notification
    keywords_with_attachment:
      - critical

# If you have configured global_keywords and don't need container specific settings
# you can leave the container config blank.
  another-containers-name:
```

 </details>


<details><summary><em>Click to expand:</em><strong> 🌍 global_keywords </strong></summary>

```yaml
# This section is optional.
# These keywords are being monitored for all containers. 
global_keywords:              
  keywords:
    - error
  # When one of these keywords is found a logfile is attached
  keywords_with_attachment:
    - regex: (critical|error)
```

</details>

[Here](/config.yaml) you can find a full example config.


### 🍀 Enviroment Variables

Except for container specific settings and regex patterns you can configure most settings via docker environment variables in either your docker compose or an .env file

<details><summary><em>Click to expand:</em><strong> Enviroment Variables </strong></summary><br>


| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| **`NTFY_URL`**                      | URL of your Ntfy server instance                    | _N/A_    |
| `NTFY_TOKEN`                    | Authentication token for Ntfy in case you need authentication.      | _N/A_    |
| `NTFY_TOPIC`                    | Notification topic for Ntfy.                             | _N/A_  |
| `NTFY_TAGS`                     | Ntfy [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications. | kite,mag  |
| `NTFY_PRIORITY`                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| `APPRISE_URL`                   | Any [Apprise-compatible URL](https://github.com/caronc/apprise/wiki)  | _N/A_    |
| `CONTAINERS`       | A comma separated list of containers to use with global keywords.<br>These are added to the containers from the config.| _N/A_     |
| `GLOBAL_KEYWORDS`       | Keywords that will be monitored for all containers. Overrides `global_keywords.keywords` from the config.yaml.| _N/A_     |
| `GLOBAL_KEYWORDS_WITH_ATTACHMENT`       | Notifications triggered by these global keywords have a logfile attached. Overrides `global_keywords.keywords_with_attachment` from the config.yaml.| _N/A_     |
| `NOTIFICATION_COOLDOWN`         | Cooldown period (in seconds) per container per keyword<br> before a new message can be sent  | 5        |
| `LOG_LEVEL`                     | Log Level for LoggiFly container logs.                    | INFO     |
| `MULTI_LINE_ENTRIES`            | When enabled the program tries to catch entries that span multiple log lines.<br>If you encounter bugs or you simply don't need it you can disable it.| True     |
| `ATTACHMENT_LINES`              | Define the number of Log Lines in the attachment file     | 20     |
| `DISABLE_RESTART`               | Disable automatic restarts when the config file is changed.| False     |
| `DISBLE_START_MESSAGE`          | Disable startup message.                                  | False     |
| `DISBLE_SHUTDOWN_MESSAGE`       | Disable shutdown message.                                 | False     |
| `DISABLE_RESTART_MESSAGE`       | Disable message on config change when program restarts.| False     |

</details>

---

## 💡 Tips

1. If you want to **Protect Sensitive Credentials** like tokens or Apprise URLs, store them in environment variables (not in YAML).
2. Ensure containers names **exactly match** your Docker **container names**. 
    - ```docker ps --format "{{.Names}}" ```
    - 💡 Pro Tip: Define the `container_name:` in your compose files. 
3. **Troubleshooting Multi-Line Logs**. If multi-line entries aren't detected:
    - Wait for Patterns: LoggiFly needs a few lines to detect the pattern the log entries start with (e.g. timestamps/log formats)
    - Unrecognized Patterns: If issues persist, open an issue and share the affected log samples
4. **Test Regex Patterns**: Validate patterns at [regex101.com](https://regex101.com) before adding them to your config.
Example for error detection:
`regex: \b(ERROR|CRITICAL)\b`
---

## License
[MIT](https://github.com/clemcer/LoggiFly/blob/main/LICENSE)
