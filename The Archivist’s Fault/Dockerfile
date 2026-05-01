FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY source ./source

EXPOSE 8080 31337
CMD ["bash", "-lc", "python3 source/chall.py plate --host 0.0.0.0 --port 31337 & exec python3 source/chall.py web --host 0.0.0.0 --port 8080"]
