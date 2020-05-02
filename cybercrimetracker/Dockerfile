FROM python:3.7-alpine


# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add build-base libmagic libxml2 libxml2-dev libxslt libxslt-dev

# Copy the connector
COPY src /opt/opencti-connector-cybercrimetracker

RUN cd /opt/opencti-connector-cybercrimetracker && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
