FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

COPY src/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apk del git build-base

COPY src /opt/opencti-connector-zvelo
WORKDIR /opt/opencti-connector-zvelo

CMD ["python3", "main.py"]
