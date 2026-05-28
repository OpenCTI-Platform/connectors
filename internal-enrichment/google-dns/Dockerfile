FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

COPY src /opt/connector/src
WORKDIR /opt/connector

RUN pip install -r /opt/connector/src/requirements.txt

RUN apk del git build-base

# Expose and entrypoint
CMD ["python", "-m", "src"]