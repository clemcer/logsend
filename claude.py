import os
import yaml
import logging
import docker
import threading
import apprise
from datetime import datetime

# Logging-Konfiguration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", mode="w"),
        logging.StreamHandler()
    ]
)

def load_config():
    """
    Lädt die Konfiguration aus config.yaml und ergänzt sie mit Umgebungsvariablen.
    """
    config = {}
    try:
        with open("config.yaml", "r") as file:
            config = yaml.safe_load(file)
            logging.info("Konfigurationsdatei erfolgreich geladen.")
    except FileNotFoundError:
        logging.warning("config.yaml nicht gefunden. Verwende nur Umgebungsvariablen.")

    config["ntfy"] = {
        "url": os.getenv("NTFY_URL", config.get("ntfy", {}).get("url", "")),
        "topic": os.getenv("NTFY_TOPIC", config.get("ntfy", {}).get("topic", "")),
        "token": os.getenv("NTFY_TOKEN", config.get("ntfy", {}).get("token", "")),
    }
    return config

def get_container_tail_logs(container, lines=50):
    try:
        logs = container.logs(tail=lines, timestamps=True).decode('utf-8')
        return logs
    except Exception as e:
        logging.error(f"Fehler beim Holen der Tail-Logs: {e}")
        return ""

def send_notification(config, container_name, message, logs_tail=""):
    apobj = apprise.Apprise()
    
    # NTFY Konfiguration
    ntfy_url = f"ntfy://{config['ntfy']['token']}@{config['ntfy']['url']}/{config['ntfy']['topic']}"
    apobj.add(ntfy_url)
    
    # Nachricht mit Logs erstellen
    title = f"Container: {container_name}"
    body = message
    if logs_tail:
        body += f"\n\nLetzte Logs:\n{logs_tail}"
    
    try:
        apobj.notify(
            body=body,
            title=title,
            tag="warning"
        )
        logging.info(f"Benachrichtigung gesendet für {container_name}")
    except Exception as e:
        logging.error(f"Fehler beim Senden der Benachrichtigung: {e}")

def monitor_container_logs(container, config, timeout=30):
    """
    Überwacht die Logs eines Containers und sendet Benachrichtigungen bei Schlüsselwörtern.
    """
    container_config = config['containers'][container.name]
    keywords = container_config.get('keywords', [])
    now = datetime.now()

    try:
        log_stream = container.logs(stream=True, follow=True, since=now)
        logging.info(f"Starte Überwachung für Container: {container.name}")

        for log_line in log_stream:
            try:
                log_line_decoded = log_line.decode("utf-8").strip()

                if log_line_decoded and any(keyword in log_line_decoded for keyword in keywords):
                    logging.info(f"Schlüsselwort gefunden in {container.name}: {log_line_decoded}")
                    # Hole die letzten Logs
                    tail_logs = get_container_tail_logs(container)
                    send_notification(config, container.name, log_line_decoded, tail_logs)

            except UnicodeDecodeError:
                logging.warning(f"Fehler beim Dekodieren einer Log-Zeile von {container.name}")
    except Exception as e:
        logging.error(f"Fehler bei der Überwachung von {container.name}: {e}")

def monitor_docker_logs(config):
    """
    Erstellt Threads zur Überwachung der Container-Logs.
    """
    client = docker.from_env()
    containers = client.containers.list()
    selected_containers = [c for c in containers if c.name in config['containers']]

    logging.info(f"Ausgewählte Container zur Überwachung: {[c.name for c in selected_containers]}")

    threads = []
    for container in selected_containers:
        thread = threading.Thread(target=monitor_container_logs, args=(container, config))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    logging.info("Log-Monitor gestartet.")
    config = load_config()
    send_notification(config, "Log-Monitor", "Das Programm läuft und überwacht Container.")
    monitor_docker_logs(config)
