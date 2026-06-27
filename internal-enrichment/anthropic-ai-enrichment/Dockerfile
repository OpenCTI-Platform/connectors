FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /opt/opencti-connector-anthropic-ai-enrichment

COPY src/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src .

CMD ["python", "main.py"]
