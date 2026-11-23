FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy only requirements, to cache them in docker layer
WORKDIR /opt/opencti-connector-orange-cyberdefense-v3
COPY src/requirements.txt ./

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libffi-dev libxslt-dev libxml2-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev libxslt-dev libxml2-dev

# Now copy all the rest of the application
COPY src .

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]