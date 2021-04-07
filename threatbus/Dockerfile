FROM python:3.8-alpine

# Install dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev libzmq zeromq-dev musl-dev python3-dev

# Prep paths & install Python modules
WORKDIR /opt/opencti-connector-threatbus
COPY src/requirements.txt .

RUN pip3 install --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@4.3.5 && \
    pip3 install --no-cache-dir -r requirements.txt

# Reduce image size by cleaning up the build packages
RUN apk del build-base musl-dev python3-dev zeromq-dev

# Copy the connector
COPY src ./

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
