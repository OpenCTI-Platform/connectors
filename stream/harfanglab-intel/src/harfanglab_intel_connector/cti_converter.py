from .models import harfanglab, opencti
from .utils import parse_stix_pattern

IOC_TYPES_BY_OBJECT_PATH = {
    "domain-name:value": "domain_name",
    "hostname:value": "domain_name",
    "ipv4-addr:value": "ip_both",
    "ipv6-addr:value": "ip_both",
    "file:name": "filename",
    "file:hashes": "hash",
}


class CTIConverter:
    def __init__(self, config):
        """
        Init CTI Converter.
        Convert OpenCTI entities into Harfanlab entities.
        :param config: Connector's config
        """
        self.config = config

    def create_ioc_rule(
        self, indicator: opencti.Indicator, observable: opencti.Observable
    ) -> harfanglab.IOCRule:
        """
        Create a Harfanglab IOC rule based on an observable and the indicator referencing it.
        :param indicator: OpenCTI Indicator referencing observable
        :param observable: OpenCTI Observable to create IOC rule for
        :return: Harfanglab IOC rule
        """
        ioc_type = CTIConverter._get_ioc_type_from_stix_pattern(
            indicator.pattern, observable
        )

        ioc_rule = harfanglab.IOCRule(
            type=ioc_type,
            value=observable.value,
            description=indicator.description,  # or "No description",
            comment={
                "indicator_id": indicator.standard_id,
                "indicator_score": indicator.x_opencti_score,
                "indicator_platforms": indicator.x_opencti_platforms,
            },
            hl_status=self.config.harfanglab_rule_maturity,
            enabled=True,
        )
        return ioc_rule

    def create_sigma_rule(self, indicator: opencti.Indicator) -> harfanglab.SigmaRule:
        """
        Create a Harfanglab Sigma rule based on an observable and the indicator referencing it.
        :param indicator: OpenCTI Indicator referencing observable
        :return: Harfanglab IOC rule
        """
        sigma = harfanglab.SigmaRule(
            content=indicator.pattern,
            name=indicator.name,
            hl_status=self.config.harfanglab_rule_maturity,
            enabled=True,
        )
        return sigma

    def create_yara_file(self, indicator: opencti.Indicator) -> harfanglab.YaraFile:
        """
        Create a Harfanglab Yara file based on an observable and the indicator referencing it.
        :param indicator: OpenCTI Indicator referencing observable
        :return: Harfanglab IOC rule
        """
        yara = harfanglab.YaraFile(
            content=indicator.pattern,
            name=indicator.name,
            hl_status=self.config.harfanglab_rule_maturity,
            enabled=True,
        )
        return yara

    @staticmethod
    def _get_ioc_type_from_stix_pattern(
        stix_pattern: str, observable: opencti.Observable
    ) -> str:
        """
        Get IOC rule type based on an OpenCTI observable referenced in STIX pattern.
        :param stix_pattern: STIX pattern referencing observable
        :param observable: OpenCTI observable referenced in STIX pattern
        :return: IOC rule type
        """
        ioc_type = None
        parsed_patterns = parse_stix_pattern(stix_pattern)
        if parsed_patterns:
            object_path = next(
                parsed_pattern["attribute"].split(".")[0]
                for parsed_pattern in parsed_patterns
                if parsed_pattern["value"] == observable.value
            )
            ioc_type = IOC_TYPES_BY_OBJECT_PATH[object_path]
        return ioc_type
