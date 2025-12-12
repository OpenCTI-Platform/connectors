FROM python:3.12-alpine
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
COPY src /opt/opencti-connector-attribution-tools

# Install dependencies
RUN apk update && apk upgrade && \
    apk --no-cache add gcc git build-base libmagic libffi-dev \
    gfortran openblas openblas-dev xsimd xsimd-dev

# Install Python modules
RUN cd /opt/opencti-connector-attribution-tools && \
    uv pip install --system --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
