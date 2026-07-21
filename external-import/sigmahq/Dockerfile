FROM python:3.12-alpine

# Install Python modules
# hadolint ignore=DL3003
WORKDIR /opt/opencti-connector-sigmahq
RUN apk --no-cache add libmagic && \
    apk --no-cache add --virtual .build-deps \
        git build-base libffi-dev libxml2-dev libxslt-dev
RUN --mount=type=bind,source=./src/requirements.txt,target=requirements.txt \
    pip3 install --no-cache-dir -r requirements.txt
RUN apk del .build-deps

COPY src/ .

ENTRYPOINT ["python3", "main.py"]
