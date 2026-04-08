FROM python:3.12-alpine

WORKDIR /opt/opencti-connector-google-secops-siem 
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN --mount=type=bind,source=src/requirements.txt,target=./requirements.txt,readonly \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src .

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
