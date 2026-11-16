FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
WORKDIR /opt/opencti-connector-greynoise
COPY requirements.txt requirements.txt
COPY src .

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev

CMD ["python3", "main.py"]
