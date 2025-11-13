FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy the connector
COPY src /opt/opencti-connector-reversinglabs-spectra-intelligence-file-submission
WORKDIR /opt/opencti-connector-reversinglabs-spectra-intelligence-file-submission

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
