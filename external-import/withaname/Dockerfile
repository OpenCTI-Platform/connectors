FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-withaname
WORKDIR /opt/opencti-connector-withaname

# Install system deps (git is required for connectors-sdk git+https:// URL),
# then Python deps, then remove build deps to keep the image small.
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python3", "main.py"]
