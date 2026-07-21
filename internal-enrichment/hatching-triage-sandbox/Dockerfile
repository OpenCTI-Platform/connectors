FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

COPY src /opt/opencti-connector-hatching-triage-sandbox

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-hatching-triage-sandbox && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

WORKDIR /opt/opencti-connector-hatching-triage-sandbox
CMD ["python3", "main.py"]
