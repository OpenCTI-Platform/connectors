import configparser


class MyConfigParser(configparser.ConfigParser):
    """
    Credits for this class and the list functions go to Peter-Smit
    https://stackoverflow.com/a/11866695
    """

    def getlist(self, section, option):
        value = self.get(section, option)
        return list(filter(None, (x.strip() for x in value.splitlines())))

    def getlistint(self, section, option):
        return [int(x) for x in self.getlist(section, option)]

    def as_dict(self):
        d = dict(self._sections)
        for k in d:
            d[k] = dict(self._defaults, **d[k])
            d[k].pop("__name__", None)
        return d
