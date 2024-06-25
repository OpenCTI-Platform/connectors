FROM python:3.11-slim
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
COPY src /opt/opencti-connector-attribution-tools

# Install dependencies
RUN apt-get update && apt-get install libmagic-dev git -y

# Install Python modules
RUN cd /opt/opencti-connector-attribution-tools && \
    pip3 install --no-cache-dir -r requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
