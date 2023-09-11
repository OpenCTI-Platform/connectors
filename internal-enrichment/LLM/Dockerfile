FROM python:3.11-alpine



# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/gpt-enrichment

RUN cd /opt/gpt-enrichment && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base



# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
