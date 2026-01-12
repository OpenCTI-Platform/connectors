# syntax=docker.io/docker/dockerfile:1.20-labs
FROM python:3.12-alpine AS base

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir --upgrade pip


FROM base AS packages
COPY --parents src/ pyproject.toml /opt/

# install then clean up
RUN cd /opt/ && \
    pip3 install --no-cache-dir . && \
    apk del git build-base && \
    rm /opt/pyproject.toml && \
    rm -rf /opt/src && \ 
    rm -rf /opt/build

FROM packages AS app
# Copy the app
COPY src/main.py /opt/main.py

# Run the app
CMD ["python3", "/opt/main.py"]
