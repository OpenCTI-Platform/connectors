FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install system dependencies required by some python packages (libmagic/file)
# - update and install file (provides libmagic) and any build deps if needed
RUN apk add --no-cache file

COPY src /opt/opencti-connector
WORKDIR /opt/opencti-connector

# Install Python requirements
RUN pip3 install --no-cache-dir -r requirements.txt

# Expose and entrypoint
COPY --chmod=0755 entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]