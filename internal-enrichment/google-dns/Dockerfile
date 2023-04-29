FROM python:3.10-alpine

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && apk del git build-base

WORKDIR /opt/opencti-google-dns

COPY src/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src/*.py .

ENTRYPOINT ["python3", "main.py"]
