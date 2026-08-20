FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/connector

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY entrypoint.sh ./entrypoint.sh
COPY config.yml.sample ./config.yml.sample
RUN chmod +x ./entrypoint.sh \
    && mkdir -p /opt/connector

ENTRYPOINT ["./entrypoint.sh"]
