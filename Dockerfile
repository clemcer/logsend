FROM python:3.10-slim

# Arbeitsverzeichnis im Container
WORKDIR /app

# Kopiere das Skript und die Konfigurationsdatei in den Container
COPY loggify.py .
COPY config.yaml .

# Installiere Abhängigkeiten
RUN pip install requests pyyaml

# Standardbefehl
CMD ["python", "log_monitor.py"]
