#! /usr/bin/env sh
set -e

# Start Gunicorn
exec gunicorn -k gevent -c "$GUNICORN_CONF" lib.web.app:app
exec nginx -g daemon off
