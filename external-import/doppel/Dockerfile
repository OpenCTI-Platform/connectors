FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Set working directory and copy code
WORKDIR /opt/doppel
COPY src /opt/doppel

# Install required OS packages and Python dependencies
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy entrypoint and make executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
