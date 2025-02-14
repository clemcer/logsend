import docker
import os
import re
import time
import logging
from threading import Thread, Lock
from notifier import send_notification


logging.getLogger(__name__)

class LogProcessor:
    def __init__(self, config, container, keywords, keywords_with_file, timeout=1):
        self.config = config
        self.container_name = container.name
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

        self._set_keywords()
        # Starte Hintergrund-Thread für Timeout
        self.flush_thread = Thread(target=self._check_flush)
        self.flush_thread.daemon = True
        self.flush_thread.start()
    
    def _set_keywords(self):
        if isinstance(self.config["containers"][self.container_name], list):
            self.local_keywords.extend(self.config["containers"][self.container_name])
        elif isinstance(self.config["containers"][self.container_name], dict):
            if "keywords_with_attachment" in self.config["containers"][self.container_name]:
                self.local_keywords_with_file.extend(self.config["containers"][self.container_name]["keywords_with_attachment"])
            if "keywords" in self.config["containers"][self.container_name]:
                self.local_keywords.extend(self.config["containers"][self.container_name]["keywords"])
        else:
            logging.error(f"{self.container_name}: Error in config: keywords or keywords_with_attachment not found")
        
        for keyword in self.local_keywords + self.local_keywords_with_file:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                self.time_per_keyword[keyword["regex"]] = 0
            else:
                self.time_per_keyword[keyword] = 0


    def find_pattern(self, line):
        patterns = [
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",                           # 2025-02-13 16:36:02
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",                            # ISO 8601 - 2025-02-13T16:36:02Z
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})",         # ISO 8601 with Timezone Offset - 2025-02-13T16:36:02+00:00
            r"(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])-\d{4} \d{2}:\d{2}:\d{2}",     # 02-13-2025 16:36:02
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}",  # Feb 13, 2025 16:36:02
            r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2}\s\d{2}:\d{2}:\d{2}\sGMT[+-]\d{2}:\d{2}\s\d{4}",  # Thu Feb 13 17:37:32 GMT+01:00 2025
            r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4}",                      # Fri Feb 14 06:27:03 2025 
            r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6}",                     # 2025/02/13 17:18:50.410540
            r"\d{2}/\d{2}/\d{4}, \d{1,2}:\d{2}:\d{2}",                              # 02/14/2025, 4:23:18 AM
            r"\[(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]",                        # Log-Level in square brackets, e.g. [INFO]
            r"\(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL\)",                          # Log-Level in round brackets, e.g. (INFO)
            r"(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)",                            # Log-Level as a single word
            r"(?i)\[(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]",                    # Log-Level in square brackets, e.g. [INFO], case-insensitive
            r"(?i)\(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL\)",                      # Log-Level in round brackets, e.g. (INFO), case-insensitive
            r"(?i)\b(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\b",                    # Log-Level as a single word, case-insensitive
            r"(?i)(INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)"                         # Log-Level as a single word without word boundary, case-insensitive
        ]
                                                                 #Fri Feb 14 06:27:03 2025
        if self.pattern == "":
           # logging.debug("Searching for pattern")
            for pattern in patterns:
                if re.search(pattern, line):
                    #logging.debug(f"Found pattern: {pattern}")
                    self.pattern = pattern
                    logging.debug(f"{self.container_name}: \nFound pattern: {pattern} \In line: {line}")
                    break
                else:
                    logging.debug(f"{self.container_name}: pattern ({pattern}) did not match")

    def _check_flush(self):
        while self.running:
            time.sleep(0.1)  # Häufigere Checks für präziseres Timeout
            with self.lock:
                if (time.time() - self.log_stream_last_updated > self.log_stream_timeout) and self.buffer:
                    self._handle_and_clear_buffer()

    def process_multi_line(self, line):
        if self.pattern == "":
            self.find_pattern(line)
        with self.lock:
            if re.search(self.pattern, line):
                #logging.debug(f"Found pattern in line: {line}, \nThis is a new line")
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
        #logging.debug(f"MESSAGE: \n{message}\nMESSAGE END")
        self._search_and_send(message)
        self.buffer.clear()



    def _search_and_send(self, log_line):
        #logging.debug(f"Searching for keywords in: {log_line}, {self.local_keywords}, {self.local_keywords_with_file}")
        for keyword in self.local_keywords + self.local_keywords_with_file:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                regex_keyword = keyword["regex"]
                #logging.debug(f"Searching for regex-keyword: {regex_keyword}")
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
              #  logging.debug(f"Searching for keyword: {keyword}")
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

        log_tail = self.container.logs(tail=lines).decode("utf-8")
        with open(file_name, "w") as file:  
            file.write(log_tail)
            return file_name

    def _send_message(self, message, keyword, file_name=None):
        logging.debug(f"SENDE NACHRICHT: \n{message}\nNACHRICHT ENDE")
        send_notification(self.config, self.container_name, message, keyword, file_name)       



    def stop(self):
        self.running = False
        with self.lock:
            if self.buffer:
                self._search_and_clear()