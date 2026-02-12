FROM python:3.11-alpine

# Métadonnées
LABEL maintainer="Your Name <your.email@example.com>"

# Configuration du répertoire de travail
WORKDIR /opt/opencti-connector-assemblyline

# Installation des dépendances système
RUN apk --no-cache add git build-base libmagic libffi-dev

# Copie des fichiers requirements
COPY requirements.txt .

# Installation des dépendances Python
RUN pip3 install --no-cache-dir -r requirements.txt

# Copie du code du connecteur
COPY src/ .

# Exposition des variables d'environnement
ENV PYTHONUNBUFFERED=1

# Point d'entrée
ENTRYPOINT ["python3", "assemblyline.py"]