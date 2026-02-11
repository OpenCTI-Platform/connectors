FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-team-cymru-scout
WORKDIR /opt/opencti-connector-team-cymru-scout

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev

RUN cd /opt/opencti-connector-team-cymru-scout && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python", "main.py"]