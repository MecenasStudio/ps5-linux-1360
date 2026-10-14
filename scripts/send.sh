#!/usr/bin/env bash
#
# Send the payload to the console's payload loader.
#
#   ./scripts/send.sh [payload.elf]
#
# PS5_IP and PS5_PORT override the defaults below.
#
# The loader is elfldr, which reads the ELF from the socket until it closes, so
# whatever sends it must close the write side when the file ends. Both tools here
# do that on their own: nc when its stdin reaches EOF, socat when the file does.
#
# Do not add -N to the nc call. Apple's nc, the one that ships with macOS, defines
# -N as "number of probes before a write timeout" and wants a number there, so
# passing the hostname fails with "invalid tcp adaptive write timeout value" and
# nothing is sent; OpenBSD's and GNU's define it as "shut down after EOF". Since
# the behaviour is already what we want, the flag is left out.

set -euo pipefail

default_payload="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/ps5-linux-1360.elf"
payload="${1:-$default_payload}"
host="${PS5_IP:-192.168.1.159}"
port="${PS5_PORT:-9021}"

if [[ ! -f "$payload" ]]; then
  echo "no such payload: $payload" >&2
  exit 1
fi

echo "sending $(basename "$payload") to $host:$port"

if command -v nc >/dev/null 2>&1; then
  nc "$host" "$port" < "$payload"
elif command -v socat >/dev/null 2>&1; then
  socat -t 99999999 - "TCP:$host:$port" < "$payload"
else
  echo "need nc or socat on PATH" >&2
  exit 1
fi

echo "sent"
