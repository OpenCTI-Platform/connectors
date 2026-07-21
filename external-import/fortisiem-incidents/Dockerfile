FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
WORKDIR /opt/opencti-connector-fortisiem-incidents
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY src/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src .

ENTRYPOINT ["python3", "main.py"]
