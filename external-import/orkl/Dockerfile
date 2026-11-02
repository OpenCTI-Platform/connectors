FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk --no-cache add git build-base libmagic libffi-dev
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apk del git build-base

COPY src /opt/connector
WORKDIR /opt/connector

ENTRYPOINT ["python", "main.py"]
