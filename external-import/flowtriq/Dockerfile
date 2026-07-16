FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV CONNECTOR_DURATION_PERIOD=PT1H

RUN apk --no-cache add libmagic libffi libxml2 libxslt

# Copy the connector
COPY src /opt/flowtriq
WORKDIR /opt/flowtriq

# Install Python modules (build deps removed after install)
RUN apk --no-cache add --virtual .build-deps git build-base libffi-dev libxml2-dev libxslt-dev && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
