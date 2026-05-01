FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY source/ /app/
RUN gcc -O2 -Wall -Wextra -Wno-unused-parameter -o /app/vault /app/vault.c \
    && rm -f /app/vault.c \
    && chmod +x /app/run.sh \
    && useradd --system --no-create-home --uid 10001 orchard \
    && chown -R orchard:orchard /app

USER orchard

EXPOSE 8080 31337

CMD ["/app/run.sh"]
