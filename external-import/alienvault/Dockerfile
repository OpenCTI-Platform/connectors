FROM python:3.11-alpine

COPY requirements.txt /opt/opencti-connector-alienvault/

RUN apk update
RUN apk upgrade
RUN apk add git
RUN apk add build-base
RUN apk add libmagic
RUN apk add libffi-dev
RUN cd /opt/opencti-connector-alienvault && pip install --no-cache-dir -r requirements.txt
# Copy the connector
COPY src /opt/opencti-connector-alienvault

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
