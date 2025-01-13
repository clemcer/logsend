import os
import yaml
import logging
import requests
import docker
import threading
from datetime import datetime


# Logging-Konfiguration
logging.basicConfig(
    level=logging.INFO,  # Ändere dies von INFO zu DEBUG
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

    # Ergänze oder überschreibe Konfigurationswerte mit Umgebungsvariablen
    config["ntfy"] = {
        "url": os.getenv("NTFY_URL", config.get("ntfy", {}).get("url", "")),
        "topic": os.getenv("NTFY_TOPIC", config.get("ntfy", {}).get("topic", "")),
        "token": os.getenv("NTFY_TOKEN", config.get("ntfy", {}).get("token", "")),
        "priority": os.getenv("NTFY_PRIORITY", config.get("ntfy", {}).get("priority", "default")),
    }
    config["containers"] = config.get("containers", [])
    config["keywords"] = config.get("keywords", ["error", "warning", "critical"])
    return config

def send_ntfy_notification(config, container_name, message):
    """
    Sendet eine Benachrichtigung an den ntfy-Server.
    """
    ntfy_url = config["ntfy"]["url"]
    ntfy_topic = config["ntfy"]["topic"]
    ntfy_token = config["ntfy"]["token"]

    if not ntfy_url or not ntfy_topic or not ntfy_token:
        logging.error("Ntfy-Konfiguration fehlt. Benachrichtigung nicht möglich.")
        return

    headers = {
        "Authorization": f"Bearer {ntfy_token}",
        "Content-Type": "text/plain", # Wichtig: Wir senden reinen Text
        "Tags": f"warning"
    }
    
    # Die Nachricht direkt als Text, nicht als Dictionary
    message_text = f"[{container_name}] {message}"

    try:
        # Sende die Nachricht direkt als Text
        response = requests.post(
            f"{ntfy_url}/{ntfy_topic}", 
            data=message_text,  # Direkt den Text senden
            headers=headers
        )
        if response.status_code == 200:
            logging.info("Ntfy-Benachrichtigung erfolgreich gesendet: %s", message)
        else:
            logging.error("Fehler beim Senden der Benachrichtigung: %s", response.text)
    except requests.RequestException as e:
        logging.error("Fehler bei der Verbindung zu ntfy: %s", e)

def monitor_container_logs(container, keywords, config, timeout=30):
    """
    Überwacht die Logs eines Containers und sendet Benachrichtigungen bei Schlüsselwörtern.
    """
    now = datetime.now()


    try:
        log_stream = container.logs(stream=True, follow=True, since=now)
        logging.info("Starte Überwachung für Container: %s", container.name)

        for log_line in log_stream:
            try:
                # Stelle sicher, dass log_line_decoded ein String ist
                log_line_decoded = str(log_line.decode("utf-8")).strip()
                #logging.info("[%s] %s", container.name, log_line_decoded)

                # Prüfe ob log_line_decoded nicht leer ist
                if log_line_decoded:
                    # Schlüsselwörter überprüfen
                    if any(str(keyword) in log_line_decoded for keyword in keywords):
                        logging.info("Schlüsselwort gefunden in %s: %s", container.name, log_line_decoded)
                        send_ntfy_notification(config, container.name, log_line_decoded)

            except UnicodeDecodeError:
                logging.warning("Fehler beim Dekodieren einer Log-Zeile von %s", container.name)
    except docker.errors.APIError as e:
        logging.error("Docker API-Fehler für Container %s: %s", container.name, e)
    except Exception as e:
        logging.error("Fehler bei der Überwachung von %s: %s", container.name, e)
        # Füge hier zusätzliches Logging hinzu
        logging.error("Fehlerdetails: %s", str(e.__class__.__name__))

def monitor_docker_logs(config):
    """
    Erstellt Threads zur Überwachung der Container-Logs.
    """
    keywords = config["keywords"]
    monitored_containers = config["containers"]
    client = docker.from_env()
    containers = client.containers.list()
    selected_containers = [c for c in containers if c.name in monitored_containers]

    logging.info("Ausgewählte Container zur Überwachung: %s", [c.name for c in selected_containers])

    threads = []
    for container in selected_containers:
        thread = threading.Thread(target=monitor_container_logs, args=(container, keywords, config))
        threads.append(thread)
        thread.start()

    # Warte, bis alle Threads abgeschlossen sind
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    # Testbenachrichtigung
    logging.info("Log-Monitor gestartet.")
    config = load_config()
    send_ntfy_notification(config, "Log-Monitor", "Das Programm läuft und überwacht Container.")
    monitor_docker_logs(config)
