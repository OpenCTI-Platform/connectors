FROM python:3.12-alpine

# Install dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev

# Copy the worker
WORKDIR /opt/connector-anyrun-task

# Install Python modules
COPY src/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the source code
COPY src .

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]