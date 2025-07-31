#!/opt/va2am/.venv/bin/python

import sys
import os

sys.path.insert(0, "/opt/va2am")
sys.path.insert(0, "/opt/va2am/lib/web")
sys.path.insert(0, "/opt/va2am/lib/")
sys.path.insert(0, "/opt/va2am/.venv/lib/python3.12/site-packages")

os.chdir("/opt/va2am")

from lib.web.app import app as application
