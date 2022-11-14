FROM python:3.10-alpine

# Copy the connector
COPY src /opt/opencti-connector-orange-cyberdefense

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxslt libxslt-dev libxml2 libxml2-dev && \
    cd /opt/opencti-connector-orange-cyberdefense && \
    pip3 install --no-cache-dir -r requirements.txt && \
    && pip3 install \
        --upgrade \
        --force \
        --no-cache-dir \
        git+https://github.com/OpenCTI-Platform/client-python@master && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
