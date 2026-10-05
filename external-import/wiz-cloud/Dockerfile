FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# git is needed while requirements.txt points at a git dependency
RUN apk add --no-cache git

COPY requirements.txt /opt/wiz-cloud/requirements.txt
RUN pip install --no-cache-dir -r /opt/wiz-cloud/requirements.txt

COPY src /opt/wiz-cloud
WORKDIR /opt/wiz-cloud

CMD ["python", "main.py"]
