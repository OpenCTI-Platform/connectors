FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
WORKDIR /opt/opencti-connector-opencti-stream
RUN apk --no-cache add git build-base libmagic libffi-dev
RUN --mount=type=bind,source=./src/requirements.txt,target=requirements.txt \
    pip3 install --no-cache-dir -r requirements.txt
RUN apk del git build-base

COPY src/ .

ENTRYPOINT ["python3", "main.py"]
