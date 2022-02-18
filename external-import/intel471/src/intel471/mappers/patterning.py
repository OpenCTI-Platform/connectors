
class STIXPatterningMapper:

    @classmethod
    def wrap(cls, *components):
        return "[" + " OR ".join([f"{i} = {j}" for i, j in components]) + "]"

    # Mappers for /iocs endpoint

    @classmethod
    def map_MaliciousURL(cls, value: str) -> str:
        return cls.wrap(("url:value", f"'{value}'"))

    @classmethod
    def map_MaliciousDomain(cls, value: str) -> str:
        return cls.wrap(("domain-name:value", f"'{value}'"))

    # Mappers for /indicators endpoint

    @classmethod
    def map_url(cls, item: dict) -> str:
        value = item["url"]
        return cls.wrap(("url:value", f"'{value}'"))

    @classmethod
    def map_file(cls, item: dict) -> str:
        md5 = item["file"]["md5"]
        sha1 = item["file"]["sha1"]
        sha256 = item["file"]["sha256"]
        return cls.wrap(("file:hashes.md5", f"'{md5}'"),
                        ("file:hashes.sha1", f"'{sha1}'"),
                        ("file:hashes.sha256", f"'{sha256}'"))

    @classmethod
    def map_ipv4(cls, item: dict) -> str:
        value = item["address"]
        return cls.wrap(("ipv4-addr:value", f"'{value}'"))
