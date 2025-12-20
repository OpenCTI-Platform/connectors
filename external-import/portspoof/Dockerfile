FROM python:3.11-slim
WORKDIR /app

# Install system dependencies required by pycti
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./
CMD ["python", "-u", "main.py"]