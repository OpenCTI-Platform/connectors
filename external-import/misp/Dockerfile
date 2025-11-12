FROM python:3.12-slim
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Instala dependencias del sistema
RUN apt-get update && apt-get install -y \
    git build-essential libmagic-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia el código fuente del conector
COPY src /opt/opencti-connector-misp

# Instala dependencias de Python
WORKDIR /opt/opencti-connector-misp
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

# Copia y configura el entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
