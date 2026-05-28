FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk --no-cache add git build-base libmagic libffi-dev

COPY src/requirements.txt /tmp/

RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    apk del git build-base

COPY src/ /opt/
WORKDIR /opt/

ENTRYPOINT ["python", "-m", "connector"]
