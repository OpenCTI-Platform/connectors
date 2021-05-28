import configparser
from typing import List, Dict


class MyConfigParser(configparser.ConfigParser):
    """
    Credits for this class and the list functions go to Peter-Smit
    https://stackoverflow.com/a/11866695
    """

    def getlist(self, section: str, option: str) -> List[str]:
        value = self.get(section, option)
        return list(filter(None, (x.strip() for x in value.splitlines())))

    def getlistint(self, section: str, option: str) -> List[int]:
        return [int(x) for x in self.getlist(section, option)]

    def as_dict(self) -> Dict[str, str]:
        d = dict(self._sections)
        for k in d:
            d[k] = dict(self._defaults, **d[k])
            d[k].pop("__name__", None)
        return d
