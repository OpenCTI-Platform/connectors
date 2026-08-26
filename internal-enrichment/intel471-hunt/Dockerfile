FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/connector

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && apt-get purge -y --auto-remove git

COPY config.yml.sample ./config.yml.sample

# The cache lives on a dedicated subdirectory so a mounted volume never shadows
# the connector code in the working directory.
RUN mkdir -p /opt/connector/cache

CMD ["python", "-m", "src"]
