FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-yara
WORKDIR /opt/opencti-yara

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add gcc git build-base libffi-dev

RUN cd /opt/opencti-yara && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base gcc libffi-dev

CMD ["python", "main.py"]
