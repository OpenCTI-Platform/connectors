FROM python:3.13-slim 
ENV CONNECTOR_TYPE=STREAM

# Create working directory
WORKDIR /opt/connector-sentinelone-intel

COPY src /opt/connector-sentinelone-intel

# Install dependencies
RUN apt-get update && apt-get install -y git build-essential libmagic-dev libffi-dev libxml2-dev libxslt-dev inotify-tools procps && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apt-get clean && rm -rf /var/lib/apt/lists/*


COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
