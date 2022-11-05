FROM python:3.10

# Copy the connector
COPY src /opt/opencti-crowdsec

# Install Python modules
# hadolint ignore=DL3003
RUN pip install -r /opt/opencti-crowdsec/requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

