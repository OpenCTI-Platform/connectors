FROM python:3.10-slim

# Copy the connector
COPY src /opt/opencti-yara

# Install Python modules
# hadolint ignore=DL3003
RUN apt-get update && \
    apt-get install -y gcc git libmagic1 libffi-dev libxml2-dev libxslt-dev libssl-dev yara && \
    apt-get clean

RUN pip3 install --no-cache-dir -r /opt/opencti-yara/requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]