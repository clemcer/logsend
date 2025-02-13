import docker
import os
import re
import time
import logging
from threading import Thread, Lock
from notifier import send_notification


logging.getLogger(__name__)

# logging.basicself.config(
#         level = "INFO",
#         format="%(asctime)s - %(levelname)s - %(message)s",
#         handlers=[
#             logging.FileHandler("monitor.log", mode="w"),
#             logging.StreamHandler()
#         ]
#     )

# logging.debug("This is a Debug-Message")
# logging.info("This is a Info-Message")
# logging.warning("This is a Warning-Message")



# # Docker-Client initialisieren
# client = docker.from_env()
# container = client.containers.get("vg-backend")
# logging

class LogProcessor:
    def __init__(self, config, container_name, keywords, keywords_with_file, timeout=1):
        self.config = config
        self.container_name = container_name
        self.buffer = []
        self.log_stream_timeout = timeout
        self.log_stream_last_updated = time.time()
        self.lock = Lock()
        self.running = True

        self.pattern = ""
        self.time_per_keyword = {} 
        self.notification_cooldown = os.getenv("keyword_notification_cooldown", self.config.get("settings", {}).get("keyword_notification_cooldown", 10))
        self.local_keywords = keywords.copy()
        self.local_keywords_with_file = keywords_with_file.copy()

        # Starte Hintergrund-Thread für Timeout
        self.flush_thread = Thread(target=self._check_flush)
        self.flush_thread.daemon = True
        self.flush_thread.start()
    
    def initialize_thread(self):
        if isinstance(self.config["containers"][self.container_name], list):
            self.local_keywords.extend(self.config["containers"][self.container_name])
        elif isinstance(self.config["containers"][self.container_name], dict):
            if "keywords_with_attachment" in self.config["containers"][self.container_name]:
                self.local_keywords_with_file.extend(self.config["containers"][self.container_name]["keywords_with_attachment"])
            if "keywords" in self.config["containers"][self.container_name]:
                self.local_keywords.extend(self.config["containers"][self.container_name]["keywords"])
        else:
            logging.error("Error in config: not a list or dict not  properly configured with keywords_with_attachment and keywords attributes")
        
        for keyword in self.local_keywords + self.local_keywords_with_file:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                self.time_per_keyword[keyword["regex"]] = 0
            else:
                self.time_per_keyword[keyword] = 0


    def find_pattern(self, line):
        patterns = [
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
            r"\[(INFO|ERROR|DEBUG|WARN)\]",
            r"\(INFO|ERROR|DEBUG|WARN\)",
        ]
        if self.pattern == "":
            logging.debug("Searching for pattern")
            for pattern in patterns:
                if re.match(line, pattern):
                    logging.debug(f"Found pattern: {pattern}")
                    self.pattern = pattern
                    break

    def _check_flush(self):
        while self.running:
            time.sleep(0.1)  # Häufigere Checks für präziseres Timeout
            with self.lock:
                if (time.time() - self.log_stream_last_updated > self.log_stream_timeout) and self.buffer:
                    self._handle_and_clear_buffer()

    def process_multi_line(self, line):
        with self.lock:
            if re.search(line, self.pattern):
                logging.debug(f"Found pattern in line: {line}, \nThis is a new line")
                if self.buffer:
                    self._handle_and_clear_buffer()
                self.buffer.append(line)
            else:
                if self.buffer:
                    self.buffer.append(line)
                else:
                    # Fallback: Unexpected Format 
                    self.buffer.append(line)
            self.log_stream_last_updated = time.time()

    def _handle_and_clear_buffer(self):
        message = "\n".join(self.buffer)
        logging.debug(f"MESSAGE: \n{message}\nMESSAGE END")
        self._search_and_send(message)
        self.buffer.clear()



    def _search_and_send(self, log_line):
        for keyword in self.local_keywords + self.local_keywords_with_file:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                regex_keyword = keyword["regex"]
                if time.time() - self.time_per_keyword.get(regex_keyword) >= int(self.notification_cooldown):
                    if re.search(regex_keyword, log_line, re.IGNORECASE):
                        if keyword in self.local_keywords_with_file:
                            logging.info(f"Regex-Keyword (with attachment) '{regex_keyword}' was found in {self.container_name}: {log_line}")
                            file_name = self._log_attachment()
                            self._send_message(log_line, regex_keyword, file_name)
                        else:
                            self._send_message(log_line, regex_keyword)
                            logging.info(f"Regex-Keyword '{keyword}' was found in {self.container_name}: {log_line}")
                        self.time_per_keyword[regex_keyword] = time.time()

            elif str(keyword).lower() in log_line.lower():
                if time.time() - self.time_per_keyword.get(keyword) >= int(self.notification_cooldown):
                    if keyword in self.local_keywords_with_file:
                        logging.info(f"Keyword (with attachment) '{keyword}' was found in {self.container_name}: {log_line}") 
                        file_name = self._log_attachment()
                        self._send_message(log_line, keyword, file_name)
                    else:
                        self._send_message(log_line, keyword)
                        logging.info(f"Keyword '{keyword}' was found in {self.container_name}: {log_line}") 
                    self.time_per_keyword[keyword] = time.time()

    def _log_attachment(self):
        if isinstance(self.config.get("containers").get(self.container_name, {}), dict):
            lines = int(self.config.get("containers", {}).get(self.container_name, {}).get("attachment_lines") or os.getenv("ATTACHMENT_LINES", self.config.get("settings", {}).get("attachment_lines", 50)))
        else:
            lines = int(os.getenv("ATTACHMENT_LINES", self.config.get("settings", {}).get("attachment_lines", 50)))

        file_name = f"last_{lines}_lines_from_{self.container_name}.log"

        log_tail = self.container_name(tail=lines).decode("utf-8")
        with open(file_name, "w") as file:  
            file.write(log_tail)
            return file_name

    def _send_message(self, message, keyword, file_name=None):
        logging.debug(f"GESENDET: \n{message}\nNACHRICHT ENDE")
        send_notification(self.config, self.container_name, self.message, keyword, file_name)       



    def stop(self):
        self.running = False
        with self.lock:
            if self.buffer:
                self._search_and_clear()

# keywords = [move, test]
# keywords_with_file = []
# # Logs streamen und verarbeiten
# processor = LogProcessor(config, container.name, keywords, keywords_with_file, timeout=1)  # Timeout in Sekunden

# try:
#     for line in container.logs(stream=True, follow=True):
#         if processor.pattern == "":
#             processor.find_pattern(line.decode("utf-8").strip())
#         processor.process_multi_line(line.decode("utf-8").strip())
# except KeyboardInterrupt:
#     pass
# finally:
#     processor.stop()