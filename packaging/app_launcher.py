#!/usr/bin/env python3
"""
packaging/app_launcher.py
=========================
Standalone Windows Desktop executable entrypoint for Aegis Studio.
"""

import sys
import os
from pathlib import Path

# Ensure application modules can be found
if getattr(sys, "frozen", False):
    app_root = Path(sys._MEIPASS)
else:
    app_root = Path(__file__).resolve().parent.parent

if str(app_root) not in sys.path:
    sys.path.insert(0, str(app_root))

from aegis.gui import launch_studio

if __name__ == "__main__":
    debug_mode = "--debug" in sys.argv
    launch_studio(debug=debug_mode)
