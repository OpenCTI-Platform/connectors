FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_EXPORT_FILE

# Copy the worker
COPY src /opt/opencti-connector-export-ttps-file-navigator

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-export-ttps-file-navigator && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

WORKDIR /opt/opencti-connector-export-ttps-file-navigator
CMD ["python3", "export-ttps-file-navigator.py"]
