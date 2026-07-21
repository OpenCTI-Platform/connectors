# -*- coding: utf-8 -*-
import sys
import time
import traceback

from .osint_industries import OsintIndustriesConnector

if __name__ == "__main__":
    try:
        OsintIndustriesConnector().run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
