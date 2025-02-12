<a name="readme-top"></a>

<br />
<div align="center">
  <a href="clemcer/logsend">
    <img src="/icon.png" alt="Logo" width="300" height="auto">
  </a>

<h1 align="center">Loggifly</h1>

  <p align="center">
    <a href="https://github.com/clemcer/Loggifly/issues">Report Bug</a>
    ·
    <a href="https://github.com/clemcer/Loggifly/issues">Request Feature</a>
  </p>
</div>

<br>


**Loggifly** is a lightweight tool for monitoring Docker container logs and sending notifications when specific keywords are detected. It supports both plain text and regular expression (regex) keywords and can attach the last 50 lines of a log file when a match is found. I originally built this to use with ntfy and ntfy is recommended because it allows the most fine grained configuration. But Loggifly also supports Apprise which lets you send notifications to over 100 different services. 🚀

---

## 🚀 Features

- **🌟 100+ notification services**: Via Apprise you can send notifications to Slack, Telegram, Discord and many more services.
- **📤 Built in ntfy Support**: Send alerts to any ntfy-compatible service (self-hosted or public).
  - **🥳 Priority, Tags & Topic**: Customize priority, tags/emojis and the topic individually for each container.
- **🔍 Keyword & Regex Monitoring**: Track specific keywords or complex regex patterns in container logs.  
- **🐳 Fine-Grained Keyword Control**: You can specify keywords per container or for all containers.  
- **📁 Log Attachments**: Automatically attach a file with the last 50 log lines to notifications.  
- **⏱ Rate Limiting**: Avoid spam with per-keyword/container cooldowns.  
- **🔧 YAML Configuration**: Define containers, keywords, and notification settings in a simple config file.  
- **⚡ Auto-Restart on Config Change**: The programm restarts when it detects that the config file has been changed.


---

# Loggifly Configuration 

While there are some settings you can set via environment variables most of the configuration for Loggifly happens in the config.yaml file.
You can find a detailed walkthrough of the config file [here](https://github.com/clemcer/loggifly/blob/main/walkthrough.md).

---


## 🛠 Installation Walkthrough


1. Create a folder on your system, place your config.yaml there and edit it to fit your needs and preferences. You can find a short example config with explaininf comments [here](https://github.com/clemcer/loggifly/blob/main/config.yaml). Or you take a look at the detailed config explanation [here](https://github.com/clemcer/loggifly/blob/main/walkthrough.md).


### Installation via Docker Compose

2. Create a `docker-compose.yaml` file in your project and adjust it to your needs. In the volumes section you will have to specify the path to your config file.
If you want, you can set all of the global settings (that are not defined per container) in your compose via environment variables. Here is a list of the options. (Or use an .env file)

```yaml
version: "3.8"
services:
  Loggifly:
    image: ghcr.io/clemcer/Loggifly:latest
    container_name: Loggifly
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./Loggifly/config/config.yaml:/app/config.yaml # specify the path of your condig file on the left side of the mapping
    restart: unless-stopped
```

2. Then, run the container:

```bash
docker-compose up -d
```
---

License
[MIT](https://github.com/clemcer/loggifly/blob/main/LICENSE)
