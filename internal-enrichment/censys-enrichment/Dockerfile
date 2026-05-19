FROM python:3.12-alpine AS base
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

RUN apk update && apk upgrade && \
    apk add --no-cache  \
      build-base  \
      git  \
      libffi-dev  \
      libmagic  \
      libxml2-dev  \
      libxslt-dev

FROM base AS dependencies

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

FROM dependencies AS connector
# Copy the connector
COPY src /opt/connector
WORKDIR /opt/connector

CMD ["python3", "main.py"]