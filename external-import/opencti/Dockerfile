FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/connector
WORKDIR /opt/connector

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python", "connector.py"]