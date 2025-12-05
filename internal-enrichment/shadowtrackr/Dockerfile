FROM python:3.12-alpine

# Copy the worker
COPY src /opt/opencti-connector-shadowtrackr
WORKDIR /opt/opencti-connector-shadowtrackr

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git libmagic && \ 
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git

# Expose and entrypoint
CMD [ "python", "main.py" ]
