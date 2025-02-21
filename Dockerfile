# Basis-Bild: Python 3.10
ARG PYTHON_VERSION=3.11.4
FROM python:${PYTHON_VERSION}-slim AS base

# Arbeitsverzeichnis im Container erstellen und setzen
WORKDIR /app

# Anforderungen (Bibliotheken) in den Container kopieren
COPY requirements.txt .

##
#LABEL org.opencontainers.image.source="https://github.com/clemcer/loggifly"

# Installiere die Abhängigkeiten
RUN pip install --no-cache-dir -r requirements.txt

# Kopiere die restlichen Dateien (Skript und Konfiguration) in den Container
COPY icon.png .
COPY app/load_config.py .
COPY app/notifier.py .
COPY app/app.py .
COPY app/line_processor.py .


CMD ["python", "app.py"]