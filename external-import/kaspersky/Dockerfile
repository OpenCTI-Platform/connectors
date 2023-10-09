# The base image.
FROM python:3.11-alpine as base


# The Builder.
FROM base as builder

# Set the working directory.
WORKDIR /builder

# Install OS dependencies.
RUN apk update && \
    apk --no-cache add build-base git libxml2-dev libxslt-dev && \
    rm -rf /var/cache/apk/*

# Setup the virtual environment.
RUN python -m venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install wheel

# Install Python dependencies.
COPY src/requirements.txt ./
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt


# The Connector.
FROM base

# Copy the source and set the working directory.
COPY src /opt/opencti-connector-kaspersky
WORKDIR /opt/opencti-connector-kaspersky

# Install OS dependencies.
RUN apk update && \
    apk --no-cache add libmagic libxml2 libxslt && \
    rm -rf /var/cache/apk/*

# Copy the venv from the builder.
COPY --from=builder /venv /venv

# Entrypoint.
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
