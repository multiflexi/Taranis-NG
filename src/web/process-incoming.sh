#!/bin/bash

cd /opt/va2am/
PYTHONPATH=. poetry run python3 lib/report/process_incoming.py --silent
