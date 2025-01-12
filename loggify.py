import os
import yaml
import logging
import requests
import docker

# Logging-Konfiguration
logging.basicConfig(
    level=logging.INFO,  # Mindest-Log-Level
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log-Ausgabeformat
    filename="monitor.log",  # Datei, in die Logs geschrieben werden
    filemode="w",  # Überschreibt Log-Datei bei jedem Start
)

def load_config():
    """
    Lädt die Konfiguration aus config.yaml und ergänzt diese mit Umgebungsvariablen.
    """
    config = {}
    try:
        with open("config.yaml", "r") as file:
            config = yaml.safe_load(file)
            logging.info("Konfigurationsdatei erfolgreich geladen.")
    except FileNotFoundError:
        logging.warning("Warnung: config.yaml nicht gefunden. Verwende nur Umgebungsvariablen.")

    # Umgebungsvariablen überschreiben YAML-Werte
    config["ntfy"] = {
        "url": os.getenv("NTFY_URL", config.get("ntfy", {}).get("url", "")),
        "topic": os.getenv("NTFY_TOPIC", config.get("ntfy", {}).get("topic", "")),
        "token": os.getenv("NTFY_TOKEN", config.get("ntfy", {}).get("token", "")),
        "priority": os.getenv("NTFY_PRIORITY", config.get("ntfy", {}).get("priority", "default")),
    }
    config["containers"] = os.getenv("MONITORED_CONTAINERS", config.get("containers", []))
    if isinstance(config["containers"], str):
        config["containers"] = config["containers"].split(",")
    
    config["keywords"] = os.getenv("MONITOR_KEYWORDS", config.get("keywords", ["error", "warning", "critical"]))
    if isinstance(config["keywords"], str):
        config["keywords"] = config["keywords"].split(",")
    
    logging.info("Konfiguration erfolgreich geladen: %s", config)
    return config

def send_ntfy_notification(container_name, message):
    """
    Sendet eine Benachrichtigung an den ntfy-Server.
    """
    config = load_config()
    ntfy_url = config["ntfy"]["url"]
    ntfy_topic = config["ntfy"]["topic"]
    ntfy_token = config["ntfy"]["token"]
    ntfy_priority = config["ntfy"]["priority"]

    if not ntfy_url or not ntfy_topic or not ntfy_token:
        logging.error("Fehler: Ntfy-URL, Topic oder Token fehlen in der Konfiguration.")
        return

    headers = {
        "Authorization": f"Bearer {ntfy_token}",
        "Title": f"Log-Monitor: {container_name}",
        "Priority": ntfy_priority,
    }

    response = requests.post(f"{ntfy_url}/{ntfy_topic}", data=message, headers=headers)
    if response.status_code == 200:
        logging.info("Ntfy-Benachrichtigung erfolgreich gesendet: %s", message)
    else:
        logging.error("Fehler beim Senden der Benachrichtigung: %s, %s", response.status_code, response.text)

def monitor_docker_logs():
    """
    Überwacht die Logs bestimmter Docker-Container und sendet Benachrichtigungen bei Schlüsselwörtern.
    """
    config = load_config()
    keywords = config["keywords"]
    monitored_containers = config["containers"]

    client = docker.from_env()
    containers = client.containers.list()
    selected_containers = [c for c in containers if c.name in monitored_containers]

    logging.info("Ausgewählte Container zur Überwachung: %s", [c.name for c in selected_containers])

    for container in selected_containers:
        logging.info("Überwache Logs von Container: %s", container.name)

        try:
            log_stream = container.logs(stream=True, follow=True)

            for log_line in log_stream:
                log_line_decoded = log_line.decode("utf-8").strip()
                if any(keyword in log_line_decoded.lower() for keyword in keywords):
                    logging.info("Treffer in %s: %s", container.name, log_line_decoded)
                    send_ntfy_notification(container.name, log_line_decoded)
        except docker.errors.NotFound:
            logging.warning("Container %s nicht verfügbar. Überspringe.", container.name)
        except Exception as e:
            logging.error("Fehler beim Überwachen von %s: %s", container.name, e)

if __name__ == "__main__":
    monitor_docker_logs()
