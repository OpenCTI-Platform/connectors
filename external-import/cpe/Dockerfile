FROM python:3.12-alpine

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy the connector
COPY src /opt/opencti-connector-cpe
WORKDIR /opt/opencti-connector-cpe
# Expose and entrypoint
COPY entrypoint.sh /
ENTRYPOINT ["python", "main.py"]
