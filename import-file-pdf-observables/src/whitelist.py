import os
import glob
import re


class WhiteList(dict):
    def __init__(self, basedir):
        searchdir = os.path.join(basedir, "whitelists/whitelist_*.ini")
        fpaths = glob.glob(searchdir)
        for fpath in fpaths:
            t = os.path.splitext(os.path.split(fpath)[1])[0].split("_", 1)[1]
            patterns = [line.strip() for line in open(fpath)]
            self[t] = [re.compile(p) for p in patterns]
