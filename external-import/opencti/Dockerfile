# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12.5
FROM python:${PYTHON_VERSION}-alpine AS base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk add --no-cache libmagic && pip install --no-cache-dir pycti==6.7.8

# Install dependencies
# Avoid an image layer for those files.
RUN --mount=type=bind,source=src/requirements.txt,target=requirements.txt \
    python -m pip install --no-cache-dir -r requirements.txt

# Copy the connector
COPY src .

# Execute the connector
CMD [ "python", "main.py" ]

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
