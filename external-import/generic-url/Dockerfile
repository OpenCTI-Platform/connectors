FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copier les fichiers du projet dans le conteneur
COPY src/ /opt/generic-url/
COPY requirements.txt /opt/generic-url/
COPY entrypoint.sh /entrypoint.sh

# Définir le répertoire de travail
WORKDIR /opt/generic-url

# Installer les dépendances système et Python
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/generic-url && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Rendre l'entrypoint exécutable
RUN chmod +x /entrypoint.sh

# Définir l'entrypoint
ENTRYPOINT ["sh","/entrypoint.sh"]
