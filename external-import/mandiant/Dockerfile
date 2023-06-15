FROM python:3.11-alpine

COPY src/requirements.txt /tmp/

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apk del git build-base

COPY src /opt/connector
WORKDIR /opt/connector

ENTRYPOINT ["python", "connector.py"]