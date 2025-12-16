FROM python:3.11-alpine

# Install dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev

# Set working directory
WORKDIR /opt/scout-search-connector

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the connector
COPY src ./src

# Create entrypoint
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Expose and entrypoint
ENTRYPOINT ["./entrypoint.sh"]
