FROM python:3.11-alpine

# Copy the worker
COPY src /opt/opencti-connector-hybrid-analysis-sandbox

# Install Python modules
# hadolint ignore=DL3003
RUN apk add git 
RUN apk add build-base
RUN apk add libmagic 
RUN apk add libffi-dev
RUN cd /opt/opencti-connector-hybrid-analysis-sandbox && pip3 install -r requirements.txt 
RUN apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
