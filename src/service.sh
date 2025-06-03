#! /bin/sh
set -eu
if [ -n "${TLS_CERT:-}" ]; then
    export GUNICORN_CMD_ARGS="$GUNICORN_CMD_ARGS --certfile $TLS_CERT --keyfile $TLS_KEY"
fi
exec gunicorn -b 0.0.0.0:$PORT app:app
