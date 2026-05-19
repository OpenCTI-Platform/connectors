FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-team-cymru-scout-search
WORKDIR /opt/opencti-connector-team-cymru-scout-search

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-team-cymru-scout-search && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python", "main.py"]
