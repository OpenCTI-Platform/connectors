FROM python:3.12-slim

# pycti version installed in the image. Build-time only, not a runtime setting: it does not have to
# match the OpenCTI platform version. Tested default: 7.261023.1. Override when needed with
#   PYCTI_VERSION=8.x.y docker compose build   (see README, Limitations)
ARG PYCTI_VERSION=7.261023.1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data

# libmagic is required by pycti
RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ioc-feed
COPY src/requirements.txt .
RUN pip install --no-cache-dir "pycti==${PYCTI_VERSION}" -r requirements.txt

COPY src/ ./

RUN useradd --uid 10001 --create-home app \
 && mkdir -p /data \
 && chown app:app /data
USER app

VOLUME ["/data"]
EXPOSE 8080 8443

# The compose file runs "python -m connector" (service connector) and "python -m ioc_distributor" (service feed-distributor).
CMD ["python", "-m", "connector"]
