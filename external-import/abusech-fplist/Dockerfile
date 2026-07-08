FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# System deps
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Python deps
COPY src/requirements.txt /opt/opencti-connector-abusech-fplist/requirements.txt
RUN pip3 install --no-cache-dir -r /opt/opencti-connector-abusech-fplist/requirements.txt && \
    apk del git build-base

# Source code
COPY src /opt/opencti-connector-abusech-fplist

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
