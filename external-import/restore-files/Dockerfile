FROM python:3.10-alpine

# Copy the worker
COPY src /opt/opencti-connector-restore-files

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev

RUN cd /opt/opencti-connector-restore-files && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
