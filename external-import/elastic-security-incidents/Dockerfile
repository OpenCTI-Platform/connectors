FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY src/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

COPY src /opt/opencti-connector-elastic-security-incidents
WORKDIR /opt/opencti-connector-elastic-security-incidents

CMD ["python3", "main.py"]
