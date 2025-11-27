FROM python:3.11-slim

RUN apt-get update && apt-get install -y iputils-ping curl openssl && apt-get clean

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

CMD ["python", "app/scanner.py"]
