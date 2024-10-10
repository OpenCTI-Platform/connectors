FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libmagic-dev

COPY connector.py .
COPY config.yml .

RUN pip install pycti requests pandas pyyaml

CMD ["python", "connector.py"]
