#!/bin/sh
set -eu

cd /app

python3 /app/chall.py &
WEB_PID=$!

trap 'kill -TERM "${WEB_PID}" 2>/dev/null || true' TERM INT

i=0
while [ "$i" -lt 40 ]; do
  if python3 -c "import socket; s=socket.socket(); s.settimeout(0.25); s.connect(('127.0.0.1',8080))" 2>/dev/null; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

exec socat -T 30 TCP-LISTEN:31337,reuseaddr,fork EXEC:/app/vault,stderr
