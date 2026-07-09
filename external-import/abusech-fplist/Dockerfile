FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-abusech-fplist

# System deps
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Python deps
COPY src/requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Source code
COPY src /opt/opencti-connector-abusech-fplist

# Run as PID 1 so SIGTERM/SIGINT reach the connector directly
ENTRYPOINT ["python3", "main.py"]
