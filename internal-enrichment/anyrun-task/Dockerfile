FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
COPY src /opt/connector-anyrun-task

# Install Python modules
# hadolint ignore=DL3003

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/connector-anyrun-task && \
    pip3 install --no-cache-dir -r requirements.txt


# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]