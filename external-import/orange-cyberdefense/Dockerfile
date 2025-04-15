FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy only requirements, to cache them in docker layer
WORKDIR /opt/opencti-connector-orange-cyberdefense
COPY src/requirements.txt ./

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxslt libxslt-dev libxml2 libxml2-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Now copy all the rest of the application
COPY src .

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]