#!/usr/bin/env bash
set -Eeo pipefail

if [ -z "$1" ]; then
  exec dns-server
else
  exec "$@"
fi