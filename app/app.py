import os
import yaml
import re
import logging
import docker
import threading
import traceback
import signal
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from notifier import send_notification
from line_processor import LogProcessor


shutdown_event = threading.Event()

def set_logging(config):
    log_level = os.getenv("LOG_LEVEL", config.get("settings", {}).get("log-level", "INFO")).upper()
    logging.getLogger().handlers.clear()
    logging.basicConfig(
        level = getattr(logging, log_level.upper(), logging.INFO),
       # level = "DEBUG",
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("monitor.log", mode="w"),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Log-Level set to {log_level}")
    logging.debug("This is a Debug-Message")
    logging.info("This is an Info-Message")
    logging.warning("This is a Warning-Message")

def handle_signal(signum, frame):
    if bool(os.getenv("DISABLE_SHUTDOWN_MESSAGE", config.get("settings", {}).get("disable_shutdown_message", False))) == False:
        send_notification(config, "Loggifly:", "The programm is shutting down.")

    logging.info(f"Signal {signum} received. shutting down...")
    shutdown_event.set() 

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)




def load_config():
    """
    Lädt die Konfiguration aus config.yaml und ergänzt sie mit Umgebungsvariablen.
    """
    config = {}
    try:
        with open("/app/config.yaml", "r") as file:
            config = yaml.safe_load(file)
            logging.info("Konfigurationsdatei erfolgreich geladen.")
    except FileNotFoundError:
        logging.warning("config.yaml nicht gefunden. Verwende nur Umgebungsvariablen.")

    config.setdefault("notifications", {})
    config.setdefault("settings", {})
    allowed_keys = {"notifications", "settings", "containers", "global_keywords"}
    for key in list(config.keys()):  # Wichtiger Hinweis: Liste der Keys erstellen, um die Iteration zu sichern.
        if key not in allowed_keys:
            del config[key]


    config["notifications"]["ntfy"] = {
        "url": os.getenv("NTFY_URL", config["notifications"].get("ntfy", {}).get("url", "")),
        "topic": os.getenv("NTFY_TOPIC", config["notifications"].get("ntfy", {}).get("topic", "")),
        "token": os.getenv("NTFY_TOKEN", config["notifications"].get("ntfy", {}).get("token", "")),
        "priority": os.getenv("NTFY_PRIORITY", config["notifications"].get("ntfy", {}).get("priority", "3")),
        "tags": os.getenv("NTFY_TAGS", config["notifications"].get("ntfy", {}).get("tags", "kite, mag")),
    }

    config["notifications"]["apprise"] = {
        "url": os.getenv("APPRISE_URL", config["notifications"].get("apprise", {}).get("url", "")),
    }
    config["containers"] = config.get("containers", [])


    config["settings"] = {
        "multi_line_entries": os.getenv("MULTI_LINE_ENTRIES", config.get("settings", {}).get("multi_line_entries", True)),
        "notification_cooldown": os.getenv("NOTIFICATION_COOLDOWN", config.get("settings", {}).get("notification_cooldown", 10))
    }
 

    
    return config


def restart_docker_container():
    if bool(os.getenv("DISABLE_RESTART_MESSAGE", config.get("settings", {}).get("disable_restart_message", False))) == False:
        send_notification(config, "Loggifly:", "Config Change detected. The programm is restarting.")
    logging.debug("restart_docker_container function was called")
    client = docker.from_env()
    container_id = os.getenv("HOSTNAME")  # Docker setzt HOSTNAME auf die Container-ID
    container = client.containers.get(container_id)
    logging.debug(f"container_id: {container_id}, container: {container}")
    container.restart()


class ConfigHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('config.yaml'):
            logging.debug("File has changed!")
            logging.info("Restarting container in 5s")
            restart_docker_container()


def detect_config_changes():
    logging.debug("watching for config changes")
    path = "/app/config.yaml"  # Pfad zur config.yaml
    event_handler = ConfigHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=False)    
    observer.start()
    try:
        while not shutdown_event.is_set():
            observer.join(1)
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        observer.stop()
        observer.join()



def monitor_container_logs(config, client, container, keywords, keywords_with_file):
    """
    Überwacht die Logs eines Containers und sendet Benachrichtigungen bei Schlüsselwörtern.
    """
    now = datetime.now()
    local_keywords = keywords.copy()
    local_keywords_with_file = keywords_with_file.copy()
  
    processor = LogProcessor(config, container, local_keywords, local_keywords_with_file, shutdown_event, timeout=5)  
    
    try:
        log_stream = container.logs(stream=True, follow=True, since=now)
        logging.info("Monitoring for Container started: %s", container.name)

        for log_line in log_stream:
            if shutdown_event.is_set():
                logging.debug(f"Noticed that shutdown_event.is_set in monitor_container_logs() function for {container.name}. Closing client now")
                client.close()
                break
            try:
                log_line_decoded = str(log_line.decode("utf-8")).strip()
                #logging.debug(f"Log-Line: {log_line_decoded}")
                if log_line_decoded:
                    processor.process_line(log_line_decoded)
            except UnicodeDecodeError:
                logging.warning("Fehler beim Dekodieren einer Log-Zeile von %s", container.name)
    except docker.errors.APIError as e:
        logging.error("Docker API-Fehler für Container %s: %s", container.name, e)
    except Exception as e:
        logging.error("Fehler bei der Überwachung von %s: %s", container.name, e)
        # Füge hier zusätzliches Logging hinzu
        logging.error("Fehlerdetails: %s", str(e.__class__.__name__))
        logging.debug(traceback.format_exc())


    logging.info("Monitoring stopped for Container: %s", container.name)

def monitor_docker_logs(config):
    """
    Erstellt Threads zur Überwachung der Container-Logs.
    """
    threads = []

    global_keywords = [ ]
    global_keywords_with_file = [ ]
    if isinstance(config.get("global_keywords"), list):
        global_keywords = config["global_keywords"] 
    elif isinstance(config.get("global_keywords"), dict):
        if "keywords_with_attachment" in config["global_keywords"]:
            global_keywords_with_file = (config["global_keywords"]["keywords_with_attachment"])
        if "keywords" in config["global_keywords"]:
            global_keywords = (config["global_keywords"]["keywords"])
        if not "keywords_with_attachment" or "keywords" in config["global_keywords"]:
            logging.error("Error in config: global_keywords: 'attachment' or 'keywords' not properly configured")



    client = docker.from_env()
    selected_containers = [ ]
    for container in config["containers"]:
        selected_containers.append(container)
    containers = client.containers.list()

    containers_to_monitor = [c for c in containers if c.name in selected_containers]

    containers_to_monitor_str = "\n - ".join(c.name for c in containers_to_monitor)   
    unmonitored_containers = [c for c in selected_containers if c not in [c.name for c in containers_to_monitor]]
    if unmonitored_containers:
        unmonitored_containers_str = "\n \n These selected Containers are not running:\n - " + "\n - ".join(unmonitored_containers)
    else:
        unmonitored_containers_str = ""

    logging.info(f"These containers are being monitored: {[c.name for c in containers_to_monitor]} \n \
                    These containers from your config are not running {unmonitored_containers_str}")

    if bool(os.getenv("DISABLE_START_MESSAGE", config.get("settings", {}).get("disable_start_message", False))) == False:
        send_notification(config, "Loggifly", f"The programm is running and monitoring these selected Containers:\n - {containers_to_monitor_str}{unmonitored_containers_str}")
    
    for container in containers_to_monitor:
        thread = threading.Thread(target=monitor_container_logs, args=(config, client, container, global_keywords, global_keywords_with_file), daemon=True)
        threads.append(thread)
        thread.start()


    if bool(os.getenv("DISABLE_RESTART", config.get("settings", {}).get("disable_restart", False))) == False:
        thread_file_change = threading.Thread(target=detect_config_changes)
        threads.append(thread_file_change)
        thread_file_change.start()

    logging.info("Monitoring started for all selected containers. Monitoring docker events now to watch for new containers")

    for event in client.events(decode=True, filters={"event": "start"}):
        if shutdown_event.is_set():
            logging.debug(f"Noticed that shutdown_event.is_set in monitor_docker_logs() function. Closing client now")
            client.close()
            break
        id = event["Actor"]["ID"]
        container_from_event = client.containers.get(id)
        if container_from_event.name in selected_containers:
            thread = threading.Thread(target=monitor_container_logs, args=(config, client, container_from_event, global_keywords, global_keywords_with_file), daemon=True)
            threads.append(thread)
            thread.start()
            logging.info("Monitoring new container: %s", container_from_event.name)
            send_notification(config, "Loggifly", f"Monitoring new container: {container_from_event.name}")


    # for thread in threads:
    #     thread.join()

if __name__ == "__main__":
    logging.info("Loggifly started")
    config = load_config()
    set_logging(config)
    logging.info(f"Multi-Line-Mode: {config['settings']['multi_line_entries']}")
    logging.info(f"Notification-Cooldown: {config['settings']['notification_cooldown']}")
    logging.debug(config)
    monitor_docker_logs(config)
    
