import docker
import os
import re
import time
import logging
from threading import Thread, Lock
from notifier import send_notification


logging.getLogger(__name__)

class LogProcessor:
    def __init__(self, config, container, keywords, keywords_with_file, shutdown_event, timeout=1):
        self.shutdown_event = shutdown_event
        self.config = config
        self.container_name = container.name
        self.container = container
        self.multi_line = config['settings']['multi_line_entries']
        self.notification_cooldown = config['settings']['notification_cooldown']
        self.local_keywords = keywords.copy()
        self.local_keywords_with_file = keywords_with_file.copy()

        self.buffer = []
        self.log_stream_timeout = timeout
        self.log_stream_last_updated = time.time()
        self.lock = Lock()
        self.running = True
        self.patterns = []
        self.time_per_keyword = {} 

        self._initialise_keywords()
        self._find_pattern()

        # Starte Hintergrund-Thread für Timeout
        self.flush_thread = Thread(target=self._check_flush)
        self.flush_thread.daemon = True
        self.flush_thread.start()

        
    
    def _initialise_keywords(self):
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

    
        

    def _find_pattern(self):
        if not self.multi_line:
            return
     #   count = 0
        found_pattern_event = self.shutdown_event
        while not self.shutdown_event.wait(timeout=300):
         #   count += 1
            time_stamp_patterns = [
                # Matches ISO 8601 with optional timezone and milliseconds
                # Examples: "2025-02-13 16:36:02", "2025-02-13T16:36:02Z", "2025-02-13T16:36:02.123Z", "2025-02-13T16:36:02+01:00"
                r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[Z+-]\d{2}:?\d{2}|\.\d{3,6}Z?)?",

                # Matches Unix epoch time (10-digit)
                # Example: "1718292832"
                r"\b\d{10}\b",

                # Matches month names with optional suffixes and commas
                # Examples: "Feb 13, 2025 16:36:02", "February 13 2025 16:36:02"
                r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4} \d{2}:\d{2}:\d{2}",

                # Matches dates with separators (- or /) and optional month names
                # Examples: "13-02-2025 16:36:02", "13/Feb/2025 16:36:02", "02-13-2025 16:36:02"
                r"\d{1,2}[-/](?:0[1-9]|1[0-2]|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-/]\d{4}[ :T]\d{1,2}:\d{2}:\d{2}",

                # Matches dates with slashes and optional commas
                # Examples: "02/13/2025 16:36:02", "02/13/2025, 4:23:18 PM"
                r"\d{2,4}/\d{2}/\d{2,4}[, ]\d{1,2}:\d{2}:\d{2}",
            ]

            log_level_patterns = [
                # Matches log levels in square or round brackets (case-insensitive)
                # Examples: "[INFO]", "(ERROR)", "[WARNING]", "(debug)"
                r"(?i)([\[\(])(INFO|ERROR|DEBUG|WARN(ING)?|CRITICAL)([\]\)])",

                # Matches log levels as standalone words with context (case-insensitive)
                # Examples: "INFO:", "ERROR ", "WARNING)", "DEBUG]"
                r"(?i)\b(INFO|ERROR|DEBUG|WARN(ING)?|CRITICAL)\b(?=\s|:|\)|\])",
            ]

            compiled_time_stamp_patterns = [re.compile(pattern) for pattern in time_stamp_patterns]
            compiled_log_level_patterns = [re.compile(pattern) for pattern in log_level_patterns]
            tmp_patterns = {pattern: 0 for pattern in compiled_time_stamp_patterns}

            log_tail = self.container.logs(tail=100).decode("utf-8")
            for line in log_tail.splitlines():
                for pattern in compiled_time_stamp_patterns:
                    if pattern.search(line):
                        tmp_patterns[pattern] += 1
                        #logging.debug(f"container: {self.container_name}: Found pattern: {pattern} --- In line: {line}")
                        break
            sorted_patterns = sorted(tmp_patterns.items(), key=lambda x: x[1], reverse=True)
            
            total_lines = len(log_tail.splitlines())
            threshold = max(5, int(total_lines * 0.1))

            for pattern in sorted_patterns:
                if pattern[1] > threshold:
                    self.patterns.append(pattern[0])
                        
            if self.patterns == []:
                tmp_patterns = {pattern: 0 for pattern in compiled_log_level_patterns}

                for line in log_tail.splitlines():
                    for pattern in compiled_log_level_patterns:
                        if pattern.search(line):
                            tmp_patterns[pattern] += 1
                            #logging.debug(f"container: {self.container_name}: Found pattern: {pattern} --- In line: {line}")
                            break

            sorted_patterns = sorted(tmp_patterns.items(), key=lambda x: x[1], reverse=True)
        
            for pattern in sorted_patterns:
                if pattern[1] > threshold:
                    self.patterns.append(pattern[0])

            logging.debug(f"container: {self.container_name}: Found patterns: {self.patterns}")

            if self.patterns == []:
                self.multi_line = False
                logging.debug(f"container: {self.container_name}: No pattern found in log. Mode: single-line.")
            else:
                self.multi_line = True
                logging.debug(f"container: {self.container_name}: Found pattern(s) in log. Mode: multi-line.")
                # break
            # if count == 6:
            #     logging.debug(f"container: {self.container_name}: No pattern found in log after 30 minutes. Switching to single-line mode.") 
            #     break

            logging.debug(f"container: {self.container_name}: Waiting 5 minutes to check again for patterns.")

       # logging.debug(f"container: {self.container_name}: ending find_pattern thread")

    def _check_flush(self):
        while self.running:
            time.sleep(1)  # Häufigere Checks für präziseres Timeout
            with self.lock:
                if (time.time() - self.log_stream_last_updated > self.log_stream_timeout) and self.buffer:
                    self._handle_and_clear_buffer()

    def process_line(self, line):
        if self.multi_line and self.patterns != []:
            self._process_multi_line(line)
        else:
            self._search_and_send(line)

    def _process_multi_line(self, line):
        with self.lock:
            for pattern in self.patterns:
                if re.search(pattern, line):
                    #logging.debug(f"Found pattern in line: {line}, \nThis is a new line")
                    if self.buffer:
                        self._handle_and_clear_buffer()
                    self.buffer.append(line)
                    match = True
                    break
                else:
                    match = False
            if match is False:
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
                self._handle_and_clear_buffer()

