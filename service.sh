#! /bin/sh

set -eu
if [ "$DEV_MODE" = "true" ]; then
    export FLASK_RUN_CERT=${TLS_CERT:-}
    export FLASK_RUN_KEY=${TLS_KEY:-}
    exec flask run -h 0.0.0.0 -p $PORT --without-threads --debug
else
    if [ -n "${TLS_CERT:-}" ]; then
        export GUNICORN_CMD_ARGS="$GUNICORN_CMD_ARGS --certfile $TLS_CERT --keyfile $TLS_KEY"
    fi
    exec gunicorn -b 0.0.0.0:$PORT app:app
fi