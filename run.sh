#!/usr/bin/env bash
set -e

# Change to script directory
cd "$(dirname "$0")"

# Default port is 8080, can override with argument (e.g. ./run.sh 9000)
PORT="${1:-8080}"

echo "Starting LAN File Transfer Server on port ${PORT}..."
python3 server.py --port "${PORT}"
