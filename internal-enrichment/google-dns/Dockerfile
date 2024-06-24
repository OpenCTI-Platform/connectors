FROM python:3.11-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

COPY src /opt/opencti-google-dns

RUN pip install -r /opt/opencti-google-dns/requirements.txt

RUN apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]