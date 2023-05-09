FROM python:3.10-alpine

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && apk del git build-base

COPY src /opt/opencti-google-dns

RUN pip install -r /opt/opencti-google-dns/requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]