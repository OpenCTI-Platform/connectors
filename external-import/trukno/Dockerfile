FROM python:3.12-slim
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-trukno
WORKDIR /opt/opencti-connector-trukno

RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

