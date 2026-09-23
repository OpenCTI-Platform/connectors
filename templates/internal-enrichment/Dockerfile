ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-alpine AS base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/opencti-connector-template
WORKDIR /opt/opencti-connector-template

# Install Python dependencies and remove build dependencies
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]
