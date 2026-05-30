FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-yara
WORKDIR /opt/opencti-yara

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add gcc git build-base libmagic libffi-dev yara

RUN cd /opt/opencti-yara && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python", "main.py"]
