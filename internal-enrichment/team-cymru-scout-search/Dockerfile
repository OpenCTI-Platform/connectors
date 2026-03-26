FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-team-cymru-scout-search
WORKDIR /opt/opencti-connector-team-cymru-scout-search

# Copy the setup script and entrypoint
COPY setup_pattern_type.py /opt/opencti-connector-team-cymru-scout-search/setup_pattern_type.py
COPY entrypoint.sh /opt/opencti-connector-team-cymru-scout-search/entrypoint.sh
RUN chmod +x /opt/opencti-connector-team-cymru-scout-search/entrypoint.sh

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-team-cymru-scout-search && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["./entrypoint.sh"]
