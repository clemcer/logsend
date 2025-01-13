# Basis-Bild: Python 3.10
ARG PYTHON_VERSION=3.11.4
FROM python:${PYTHON_VERSION}-slim AS base

# Arbeitsverzeichnis im Container erstellen und setzen
WORKDIR /app

# Anforderungen (Bibliotheken) in den Container kopieren
COPY requirements.txt .

# Installiere die Abhängigkeiten
RUN pip install --no-cache-dir -r requirements.txt

# Kopiere die restlichen Dateien (Skript und Konfiguration) in den Container
COPY app.py .
COPY config.yaml .
COPY test.py .
COPY request_test.py .

# Setze Standard-Umgebungsvariablen (optional, können aber beim Start überschrieben werden)
#ENV NTFY_URL="https://ntfy.sh"
#ENV NTFY_TOPIC="alerts"
#ENV NTFY_TOKEN=""
#ENV NTFY_PRIORITY="default"

# Standardbefehl, um das Python-Skript auszuführen
CMD ["python", "app.py"]
