FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/connector/src
WORKDIR /opt/connector

RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libffi-dev && \
    pip3 install --no-cache-dir -r /opt/connector/src/requirements.txt && \
    apk del git build-base libffi-dev

CMD ["python", "-m", "src"]