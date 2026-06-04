FROM python:3.12-slim
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-trukno
WORKDIR /opt/opencti-connector-trukno

RUN apt-get update \
    && apt-get install -y --no-install-recommends git libmagic1 \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
