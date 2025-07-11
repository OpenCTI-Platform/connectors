FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT


# Copy everything from doppel directory (config, src, etc.)
COPY src /opt/doppel

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/doppel && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["sh","/entrypoint.sh"]
