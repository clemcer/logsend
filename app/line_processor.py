import docker
import os
import re
import time
import logging
import threading
from threading import Thread, Lock
from notifier import send_notification

class LogProcessor:

    STRICT_PATTERNS = [
            
        # combined timestamp and log level
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{3})?\] \[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]", # 
        r"^\d{4}-\d{2}-\d{2}(?:, | )\d{2}:\d{2}:\d{2}(?:,\d{3})? (?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)",
        
        # ISO in brackets
        r"^\[\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\]", # [2025-02-17T03:23:07Z] or [2025-02-17 04:22:59 +0100] or [2025-02-18T03:23:05.436627]

        # Months in brackets
        r"^\[(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\]",                                                  # [Feb 17, 2025 10:13:02]
        r"^\[\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\]", # [17/Feb/2025:10:13:02 +0000]

        # ISO without brackes
        r"^\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b",

        # Months without brackets
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\b",
        r"\b\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\b",   # 17/Feb/2025:10:13:02 +0000
        
        # Unix-like Timestamps
        r"^\[\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d{2,6}\]",
        
        # Log-Level at the beginning of the line
        r"^\[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]",
        r"^\((?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\)"
    ]

    FLEX_PATTERNS = [
            # ----------------------------------------------------------------
            # Generic Timestamps (Fallback)
            # ----------------------------------------------------------------
            
            r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
            r"\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b", # 2025-02-17T03:23:07Z
            r"\b(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])-\d{4} \d{2}:\d{2}:\d{2}\b",
            r"(?i)\b\d{2}\/\d{2}\/\d{4}(?:,\s+|:|\s+])\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?\b",
            r"\b\d{10}\.\d+\b",                                                          # 1739762586.0394847
           

            # ----------------------------------------------------------------
            # Log-Level (Fallback)
            # ----------------------------------------------------------------
            r"(?i)(?<=^)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",      
            r"(?i)(?<=\s)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",
            r"(?i)\[(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\]",
            r"(?i)\((?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\)",

            # ## TESTING BECAUSE IT DOES NOT WORK FOR IMMICH SERVER LOGS
            r"(?i)\d{2}/\d{2}/\d{4},\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)",
        ]
            
    COMPILED_STRICT_PATTERNS = [re.compile(pattern) for pattern in STRICT_PATTERNS]
    COMPILED_FLEX_PATTERNS = [re.compile(pattern) for pattern in FLEX_PATTERNS]

    def __init__(self, config, container, shutdown_event, timeout=1):
        self.shutdown_event = shutdown_event
        self.config = config
        self.container = container
        self.container_name = container.name
        self.container_keywords = list(config.global_keywords.keywords) + list(config.containers[self.container_name].keywords)
        self.container_keywords_with_file = list(config.global_keywords.keywords_with_attachment) + list(config.containers[self.container_name].keywords)
        self.lines_number_attachment = config.containers[self.container_name].attachment_lines or config.settings.attachment_lines
        self.multi_line_config = config.settings.multi_line_entries
        self.notification_cooldown = config.settings.notification_cooldown
        self.time_per_keyword = {}   
        for keyword in self.container_keywords + self.container_keywords_with_file:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                self.time_per_keyword[keyword["regex"]] = 0
            else:
                self.time_per_keyword[keyword] = 0  

        logging.debug(f"container: {self.container_name}: Keywords: {self.container_keywords}, Keywords with attachment: {self.container_keywords_with_file}")

        if self.multi_line_config is True:
            self.lock_buffer = Lock()
            self.patterns = []
            self.patterns_count = {pattern: 0 for pattern in self.__class__.COMPILED_STRICT_PATTERNS + self.__class__.COMPILED_FLEX_PATTERNS}
            time.sleep(2)
            self.line_count = 0
            self.line_limit = 200
            log_tail = self.container.logs(tail=100).decode("utf-8")
            self._find_pattern(log_tail)
            # self.refresh_pattern_thread = Thread(target=self._refresh_pattern)
            # self.refresh_pattern_thread.daemon = True
            # self.refresh_pattern_thread.start()

            self.buffer = []
            self.log_stream_timeout = timeout
            self.log_stream_last_updated = time.time()
            self.running = True
            # Start Background-Thread for Timeout
            self.flush_thread = Thread(target=self._check_flush)
            self.flush_thread.daemon = True
            self.flush_thread.start()

        

        

    
    # def _refresh_pattern(self):
    #     counter = 0
    #     while not self.shutdown_event.wait(timeout=300) and counter < 12 and self.patterns == []:
    #         counter += 1
    #         logging.debug(f"Refreshing pattern")
    #         self._find_pattern()
    #         if self.patterns is not []:
    #             logging.info(f"container: {self.container_name}: attern refreshed: {self.patterns}")
    #         else:
    #             logging.info(f"container: {self.container_name}: Pattern refreshed. No pattern found. Mode: single-line.")
    #         logging.debug(f"container: {self.container_name}: Waiting 5 minutes to check again for patterns.")
    #     logging.info(f"container: {self.container_name}: Stopping pattern-refreshing. No pattern found in log after 60 minutes. Mode: single-line.")

    def _find_pattern(self, line_s):
        self.waiting_for_pattern = True

        for line in line_s.splitlines():
            clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            self.line_count += 1
            for pattern in self.__class__.COMPILED_STRICT_PATTERNS:
                if pattern.search(clean_line):
                    self.patterns_count[pattern] += 1
                    break
            else:
                for pattern in self.__class__.COMPILED_FLEX_PATTERNS:
                    if pattern.search(clean_line):
                        self.patterns_count[pattern] += 1
                        break
  
        sorted_patterns = sorted(self.patterns_count.items(), key=lambda x: x[1], reverse=True)
        threshold = max(5, int(self.line_count * 0.1))

        for pattern in sorted_patterns:
            if pattern[0] not in self.patterns and pattern[1] > threshold:
                self.patterns.append(pattern[0])
                logging.debug(f"container: {self.container_name}: Found pattern: {pattern[0]} with {pattern[1]} matches of {self.line_count} lines. {round(pattern[1] / self.line_count * 100, 2)}%")
                self.valid_pattern = True

        if self.patterns == []:
            self.valid_pattern = False
            
        if self.line_count >= self.line_limit:
            if self.patterns == []:
                logging.info(f"container: {self.container_name}: No pattern found in log. Mode: single-line after {self.line_limit} lines.")
            else:   
                logging.info(f"container: {self.container_name}: Found pattern(s) in log. Stopping the search now after {self.line_limit}] lines. Mode: multi-line.\nPatterns: {self.patterns}")
                    #     logging.info(f"container: {self.container_name}: No pattern found in log. Mode: single-line.")

     #   logging.debug(f"container: {self.container_name}: Line_count: {self.line_count} Patterns: {sorted_patterns}")
        #     self.valid_pattern = True
        #     logging.info(f"container: {self.container_name}: Found pattern(s) in log. Mode: multi-line.\nPatterns: {self.patterns}")
        self.waiting_for_pattern = False


    def _check_flush(self):
        while not self.shutdown_event.wait(timeout=1):
            with self.lock_buffer:
                if (time.time() - self.log_stream_last_updated > self.log_stream_timeout) and self.buffer:
                    self._handle_and_clear_buffer()

    def process_line(self, line):
        clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if self.multi_line_config == False:
            self._search_and_send(clean_line)
        else:
            if self.line_count <= self.line_limit:
                self._find_pattern(clean_line)
            if self.valid_pattern == True:
                self._process_multi_line(clean_line)
            else:
                self._search_and_send(clean_line)

    def _process_multi_line(self, line):
        while self.waiting_for_pattern == True:
            time.sleep(1)

        for pattern in self.patterns:
            if pattern.search(line):
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
      #  logging.debug(f"Searching for keywords in: {log_line}, {self.local_keywords}, {self.local_keywords_with_file}")
        for keyword in self.container_keywords + self.container_keywords_with_file:
            if isinstance(keyword, dict) and keyword.get("regex") is not None:
                regex_keyword = keyword["regex"]
                #logging.debug(f"Searching for regex-keyword: {regex_keyword}")
                if time.time() - self.time_per_keyword.get(regex_keyword) >= int(self.notification_cooldown):
                    if re.search(regex_keyword, log_line, re.IGNORECASE):
                        if keyword in self.container_keywords_with_file:
                            logging.info(f"Regex-Keyword (with attachment) '{regex_keyword}' was found in {self.container_name}: {log_line}")
                            self._send_message(log_line, regex_keyword, send_attachment=True)
                        else:
                            self._send_message(log_line, regex_keyword, send_attachment=False)
                            logging.info(f"Regex-Keyword '{keyword}' was found in {self.container_name}: {log_line}")
                        self.time_per_keyword[regex_keyword] = time.time()

            elif str(keyword).lower() in log_line.lower():
               # logging.debug(f"Searching for keyword: {keyword}")
                if time.time() - self.time_per_keyword.get(keyword) >= int(self.notification_cooldown):
                    if keyword in self.container_keywords_with_file:
                        logging.info(f"Keyword (with attachment) '{keyword}' was found in {self.container_name}: {log_line}") 
                        self._send_message(log_line, keyword, send_attachment=True)
                    else:
                        self._send_message(log_line, keyword, send_attachment=False)
                        logging.info(f"Keyword '{keyword}' was found in {self.container_name}: {log_line}") 
                    self.time_per_keyword[keyword] = time.time()

    def _log_attachment(self):  
        file_name = f"last_{self.lines_number_attachment}_lines_from_{self.container_name}.log"
        log_tail = self.container.logs(tail=self.lines_number_attachment).decode("utf-8")
        with open(file_name, "w") as file:  
            file.write(log_tail)
            return file_name

    def _send_message(self, message, keyword, send_attachment=False):
       # logging.debug(f"SENDE NACHRICHT: \n{message}\nNACHRICHT ENDE")
        if send_attachment:
            file_name = self._log_attachment()
            send_notification(self.config, self.container_name, message, keyword, file_name)     
            if os.path.exists(file_name):
                os.remove(file_name)
                logging.debug(f"Die Datei {file_name} wurde gelöscht.")
            else:
                logging.debug(f"Die Datei {file_name} existiert nicht.") 
        else:
            send_notification(self.config, self.container_name, message, keyword)





