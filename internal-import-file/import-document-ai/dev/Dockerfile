FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r dev-requirements.txt
COPY . .

EXPOSE 80

CMD ["uvicorn", "fake_rest:app", "--host", "0.0.0.0", "--port", "80"]