FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV CONNECTOR_DURATION_PERIOD=PT12H

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev 

# Copy the connector
COPY src /opt/abuseipdb-ipblacklist
WORKDIR /opt/abuseipdb-ipblacklist

# Install Python modules
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
RUN apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
