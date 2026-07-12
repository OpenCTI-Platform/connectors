# -*- coding: utf-8 -*-
import sys
import time
import traceback

from .xposedornot import XposedOrNotConnector

if __name__ == "__main__":
    try:
        XposedOrNotConnector().run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
