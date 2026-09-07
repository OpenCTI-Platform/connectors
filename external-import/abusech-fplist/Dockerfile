FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-abusech-fplist

RUN apk --no-cache add git build-base libmagic libffi libffi-dev

COPY src/requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev

COPY src /opt/opencti-connector-abusech-fplist

ENTRYPOINT ["python3", "main.py"]
