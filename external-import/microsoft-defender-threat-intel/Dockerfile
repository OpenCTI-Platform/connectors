FROM python:3.12-alpine AS base
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk update && apk upgrade && \
    apk --no-cache add  build-base git  libffi-dev libmagic libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir --upgrade pip

FROM base AS connector

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apk del git build-base && \
    rm /tmp/requirements.txt

WORKDIR /opt/opencti-connector
COPY src/ .

ENTRYPOINT ["python3", "main.py"]