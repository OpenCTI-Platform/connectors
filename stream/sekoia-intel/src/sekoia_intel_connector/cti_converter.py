from .models import opencti, sekoia
from .utils import parse_stix_pattern


class CTIConverter:
    def __init__(self, config):
        """
        Init CTI Converter.
        Convert OpenCTI entities into Harfanlab entities.
        :param config: Connector's config
        """
        self.config = config

    @staticmethod
    def _get_sekoia_format(stix_format: str | None) -> str:
        """
        Fetch the format according to the indicator type
        """
        if stix_format is None:
            return "one_per_line"

        if str(stix_format).__contains__("ipv4"):
            return "ipv4-addr.value"

        if str(stix_format).__contains__("ipv6"):
            return "ipv6-addr.value"

        if str(stix_format).__contains__("domain"):
            return "domain-name.value"

        if str(stix_format).__contains__("url"):
            return "url.value"

        if str(stix_format).__contains__("email"):
            return "email-addr.value"

        if str(stix_format).__contains__("hashes"):
            return "file.hashes"

        return "one_per_line"

    def create_sekoia_ioc(
        self, indicator: opencti.Indicator
    ) -> sekoia.IOCImport | None:
        """
        Create a Sekoia IOC import based on the indicator and the observable.
        :param indicator: OpenCTI Indicator referencing observable
        :return: Sekoia IOC import
        """
        parsed_pattern = parse_stix_pattern(indicator.pattern)
        if len(parsed_pattern) == 0:
            return None

        format = self._get_sekoia_format(parsed_pattern[0]["attribute"])

        indicator_str = ""
        first = True
        for pat in parsed_pattern:
            # The sekoia Ioc import accept only string as value
            if not isinstance(pat["value"], str):
                continue
            if first:
                indicator_str = pat["value"]
                first = False
            else:
                indicator_str = "\n".join([indicator_str, pat["value"]])

        if indicator_str == "":
            return None

        description = None

        if indicator.opencti_url:
            # If the indicator has an OpenCTI URL, we can use it as a description
            description = f"{indicator.opencti_url}"

        ioc_import = sekoia.IOCImport(
            format=format,
            indicators=indicator_str,
            valid_from=indicator.valid_from,
            valid_until=indicator.valid_until,
            kill_chain_phases=indicator.kill_chain_phases,
            description=description,
        )
        return ioc_import
