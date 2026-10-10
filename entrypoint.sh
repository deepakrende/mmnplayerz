#!/bin/sh
# A Render Disk is mounted owned by root. Give the app's user access to it, then run the app without root rights.
if [ -n "$DATA_DIR" ]; then
  mkdir -p "$DATA_DIR" 2>/dev/null
  chown -R node:node "$DATA_DIR" 2>/dev/null || echo "[entrypoint] could not change owner of $DATA_DIR"
fi
if command -v su-exec >/dev/null 2>&1; then
  exec su-exec node:node node server-prod.js
else
  echo "[entrypoint] su-exec not found, starting without dropping privileges"
  exec node server-prod.js
fi
