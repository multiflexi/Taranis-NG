#!/bin/bash

cd /opt/va2am/
PYTHONPATH=. poetry run python3 lib/event/rescan.py --silent
