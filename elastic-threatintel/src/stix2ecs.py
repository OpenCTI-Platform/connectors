
import collections.abc
from typing import Dict, List, Tuple
from stix2patterns.pattern import Pattern


class StixIndicator(object):
    def __init__(self, typename: str = None) -> None:
        self.typename: str = typename

    def parse_pattern(self, pattern: str) -> None:
        p = Pattern(pattern)
        data = p.inspect().comparisons

        objs = []
        for item in data.keys():
            switch = {
                "artifact": ArtifactIndicator,
                "autonomous-system": AutonomousSystemIndicator,
                "directory": DirectoryIndicator,
                "domain-name": DomainNameIndicator,
                "email-addr": EmailAddrIndicator,
                "email-message": EmailMessageIndicator,
                "mime-part-type": EmailMimePartTypeIndicator,
                "file": FileIndicator,
                "ipv4-addr": IPv4AddrIndicator,
                "ipv6-addr": IPv6AddrIndicator,
                "mac-addr": MacAddrIndicator,
                "mutex": MutexIndicator,
                "network-traffic": NetworkTrafficIndicator,
                "process": ProcessIndicator,
                "software": SoftwareIndicator,
                "url": UrlIndicator,
                "user-account": UserAccountIndicator,
                "windows-registry-key": WindowsRegistryKeyIndicator,
                "win-registry-key": WindowsRegistryKeyIndicator,
                "x509-certificate": X509CertificateIndicator,
                "x-opencti-hostname": XOpenCTIHostnameIndicator,
            }
            objs.append(switch.get(item, UnknownIndicator)
                        (typename=item)._parse(data[item]))

        return objs

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        raise NotImplementedError(f"_parse() not implemented for `{self.typename}`")

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = {"type": self.typename}
        return obj


def recursive_update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = recursive_update(d.get(k, {}), v)
        elif k in d:
            if not isinstance(d[k], list):
                d[k] = [d.get(k)]
            if not isinstance(v, list):
                d[k].append(v)
            else:
                d[k].extend(v)
        else:
            if isinstance(v, list):
                d[k] = v
            else:
                d[k] = [v]

    return d


class UnknownIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        raise NotImplementedError


class ArtifactIndicator(StixIndicator):

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.hashes: List[Dict[str, str]] = None
        self.mime_type: List[str] = None
        self.payload_bin: List[str] = None  # not yet supported
        self.url: List[str] = None  # not yet supported

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            if item[0][0].lower() == 'hashes':
                recursive_update(obj, {"hashes": {item[0][1].lower().replace(
                    '-', ''): item[2].lower().replace("'", "")}})
            elif item[0][0].lower() == 'mime_type':
                recursive_update(
                    obj, {"mime_type": item[2].lower().replace("'", "")})

        if "hashes" in obj:
            self.hashes = obj["hashes"]
        if "mime_type" in obj:
            self.mime_type = obj["mime_type"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.hashes is not None:
            recursive_update(obj, {"file": {"hash": self.hashes}})
        if self.mime_type is not None:
            recursive_update(obj, {"file": {"mime_type": self.mime_type}})
        return obj


class AutonomousSystemIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.number: List[int] = None
        self.name: List[str] = None
        self.rir: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            if item[0][0].lower() == 'number':
                recursive_update(
                    obj, {"number": item[2]})
            elif item[0][0].lower() == 'name':
                recursive_update(
                    obj, {"name": item[2].replace("'", "")})
            elif item[0][0].lower() == 'rir':
                recursive_update(
                    obj, {"rir": item[2].replace("'", "")})

        if "number" in obj:
            self.number = obj["number"]
        if "name" in obj:
            self.name = obj["name"]
        if "rir" in obj:
            self.rir = obj["rir"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.number is not None:
            recursive_update(obj, {"as": {"number": self.number}})
        if self.name is not None:
            recursive_update(obj, {"as": {"organization": {"name": self.name}}})
        if self.rir is not None:
            recursive_update(obj, {"as": {"regional_internet_registry": self.rir}})

        return obj


class DirectoryIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class DomainNameIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.domain: List[str] = None
        self.resolves_to: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            if item[0][0].lower() == 'value':
                recursive_update(
                    obj, {"domain": item[2].replace("'", "")})
            elif item[0][0].lower() == 'resolves_to_refs':
                recursive_update(
                    obj, {"resolves_to": item[2].replace("'", "")})

        if "domain" in obj:
            self.domain = obj["domain"]
        if "resolves_to" in obj:
            self.resolves_to = obj["resolves_to"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.domain is not None:
            recursive_update(obj, {"domain": self.domain})
        if self.resolves_to is not None:
            recursive_update(obj, {"ip": self.resolves_to})
        return obj


class XOpenCTIHostnameIndicator(DomainNameIndicator):
    def __init__(self, **kwargs) -> None:
        self.typename: str = "domain-name"
        super().__init__(**kwargs)


class EmailAddrIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.address: List[str] = None
        self.display_name: List[str] = None
        self.belongs_to: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            if item[0][0].lower() == 'value':
                recursive_update(
                    obj, {"value": item[2].replace("'", "")})
            elif item[0][0].lower() == 'display_name':
                recursive_update(
                    obj, {"display_name": item[2].replace("'", "")}
                )
            elif item[0][0].lower() == 'belongs_to_refs':
                recursive_update(
                    obj, {"belongs_to": item[2].replace("'", "")})

        if "value" in obj:
            self.address = obj["value"]
        if "display_name" in obj:
            self.display_name = obj["display_name"]
        if "belongs_to" in obj:
            self.belongs_to = obj["belongs_to"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.address is not None:
            recursive_update(obj, {"email": {"address": self.address}})
        if self.display_name is not None:
            recursive_update(obj, {"email": {"display_name": self.display_name}})
        return obj


class EmailMessageIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class EmailMimePartTypeIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class FileIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.hashes: List[Dict[str, str]] = None
        self.size: List[int] = None
        self.name: List[str] = None
        self.mime_type: List[str] = None
        self.parent_directory: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            if item[0][0].lower() == 'hashes':
                recursive_update(obj, {"hashes": {item[0][1].lower().replace(
                    '-', ''): item[2].lower().replace("'", "")}})
            elif item[0][0].lower() in ('mime_type', 'name'):
                recursive_update(
                    obj, {item[0][0].lower(): item[2].lower().replace("'", "")})
            elif item[0][0].lower() == 'size':
                recursive_update(obj, {item[0][0].lower(): item[2]})

        if "hashes" in obj:
            self.hashes = obj["hashes"]
        if "mime_type" in obj:
            self.mime_type = obj["mime_type"]
        if "name" in obj:
            self.name = obj["name"]
        if "size" in obj:
            self.size = obj["size"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.hashes is not None:
            recursive_update(obj, {"file": {"hash": self.hashes}})
        if self.mime_type is not None:
            recursive_update(obj, {"file": {"mime_type": self.mime_type}})
        if self.name is not None:
            recursive_update(obj, {"file": {"name": self.name}})
        if self.size is not None:
            recursive_update(obj, {"file": {"size": self.size}})

        return obj


class IPv4AddrIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.ip: List[str] = None
        self.resolves_to: List[str] = None
        self.belongs_to: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            print(item)
            if item[0][0].lower() == 'value':
                recursive_update(
                    obj, {"ip": item[2].replace("'", "")})
            elif item[0][0].lower() == 'resolves_to_refs':
                recursive_update(
                    obj, {"resolves_to": item[2].replace("'", "")})
            elif item[0][0].lower() == 'belongs_to_refs':
                recursive_update(
                    obj, {"belongs_to": item[2].replace("'", "")})

        if "ip" in obj:
            self.ip = obj["ip"]
        if "resolves_to" in obj:
            self.resolves_to = obj["resolves_to"]
        if "belongs_to" in obj:
            self.belongs_to = obj["belongs_to"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.ip is not None:
            recursive_update(obj, {"ip": self.ip})
        if self.resolves_to is not None:
            recursive_update(obj, {"mac": self.resolves_to})
        if self.belongs_to is not None:
            recursive_update(obj, {"as": {"number": self.belongs_to}})
        return obj


class IPv6AddrIndicator(IPv4AddrIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class MacAddrIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.mac: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            print(item)
            if item[0][0].lower() == 'value':
                recursive_update(
                    obj, {"mac": item[2].replace("'", "")})

        if "mac" in obj:
            self.mac = obj["mac"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.mac is not None:
            recursive_update(obj, {"mac": self.mac})

        return obj


class MutexIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class NetworkTrafficIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.source: List[Dict[str, str]] = None
        self.destination: List[Dict[str, str]] = None
        self.protocols: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:

        from ipaddress import ip_address, ip_network

        obj: dict[str, str] = {}
        for item in data:
            print(item)

            if item[0][0].lower() in ('src_ref', 'dst_ref'):
                if item[0][1].lower() == "type":
                    continue

                if item[0][0].lower() == 'src_ref':
                    side = "source"
                elif item[0][0].lower() == 'dst_ref':
                    side = "destination"

                if item[0][1].lower() == 'value':
                    value = item[2].replace("'", "")
                    try:
                        value = f"{ip_address(value)}"
                        recursive_update(obj, {side: {"ip": value}})
                    except ValueError:
                        # Not an address, try network
                        try:
                            value = f"{ip_network(value, strict=False)}"
                            recursive_update(obj, {side: {"ip": value}})
                        except ValueError:
                            # Neither network, nor address. Use it as-is as domain
                            recursive_update(obj, {side: {"domain": value}})

            if item[0][0].lower() in ('src_port', 'dst_port'):
                if item[0][0].lower() == 'src_port':
                    side = "source"
                elif item[0][0].lower() == 'dst_port':
                    side = "destination"

                recursive_update(obj, {side: {"port": item[2]}})

            if item[0][0].lower() == "protocols":
                protos = item[2].replace("'", "").split(',')
                recursive_update(obj, {"protocols": protos})

        if "source" in obj:
            self.source = obj["source"]
        if "destination" in obj:
            self.destination = obj["destination"]
        if "protocols" in obj:
            self.protocols = obj["protocols"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.source is not None:
            recursive_update(obj, {"source": self.source})
        if self.destination is not None:
            recursive_update(obj, {"destination": self.destination})
        if self.protocols is not None:
            for item in self.protocols:
                if item.lower() in ("ipv4", "ipv6", "ipsec", "pim"):
                    recursive_update(obj, {"network": {"type": item.lower()}})
                elif item.lower() in ("tcp", "udp", "icmp", "ipv6-icmp", "icmp6"):
                    recursive_update(obj, {"network": {"transport": item.lower()}})
                else:
                    recursive_update(obj, {"network": {"protocol": item.lower()}})
        return obj


class ProcessIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.name: List[str] = None
        self.arguments: List[str] = None
        self.command_line: List[str] = None

    def _parse(self, data: List[Tuple[str, str, str]]) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        for item in data:
            if item[0][0].lower() == 'arguments':
                args = item[2].replace("'", "").split(',')
                recursive_update(obj, {"arguments": args})
            elif item[0][0].lower() in ('name', 'command_line'):
                recursive_update(
                    obj, {item[0][0].lower(): item[2].replace("'", "")})

        if "arguments" in obj:
            self.arguments = obj["arguments"]
        if "name" in obj:
            self.name = obj["name"]
        if "command_line" in obj:
            self.command_line = obj["command_line"]

        return self

    def get_ecs_indicator(self) -> Dict[str, str]:
        obj = super().get_ecs_indicator()
        if self.arguments is not None:
            recursive_update(obj, {"process": {"args": self.arguments}})
        if self.name is not None:
            recursive_update(obj, {"process": {"name": self.name}})
        if self.command_line is not None:
            recursive_update(obj, {"process": {"command_line": self.command_line}})

        return obj


class SoftwareIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class UrlIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class UserAccountIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class WindowsRegistryKeyIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class X509CertificateIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class X509v3ExtensionTypeIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class XOpenCTI_HostnameIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class XOpenCTI_CryptographicKeyIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class XOpenCTI_CryptocurrencyWalletIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class XOpenCTI_TextIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)


class XOpenCTI_UserAgentIndicator(StixIndicator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
