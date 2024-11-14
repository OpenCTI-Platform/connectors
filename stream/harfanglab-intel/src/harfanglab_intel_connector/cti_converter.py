from .models import harfanglab, opencti
from .utils import is_file_hash

IOC_TYPES_BY_OBJECT_PATH = {
    "domain-name:value": "domain_name",
    "hostname:value": "domain_name",
    "ipv4-addr:value": "ip_both",
    "ipv6-addr:value": "ip_both",
    "url:value": "url",
    "file:name": "filename",
    "file:hashes": "hash",
}

IOC_TYPES_BY_ENTITY_TYPE = {
    "domain-name": "domain_name",
    "hostname": "domain_name",
    "ipv4-addr": "ip_both",
    "ipv6-addr": "ip_both",
    "url": "url",
    "stixfile": ["filename", "hash"],
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
        ioc_type = CTIConverter._get_ioc_type(indicator, observable)

        ioc_rule = harfanglab.IOCRule(
            type=ioc_type,
            value=observable.value,
            description=indicator.description,
            comment={
                "indicator_id": indicator.standard_id,
                "indicator_score": indicator.x_opencti_score,
                "indicator_platforms": indicator.x_mitre_platforms,
            },
            hl_status=self.config.harfanglab_rule_maturity,
            enabled=True,
        )
        return ioc_rule

    def create_sigma_rule(self, indicator: opencti.Indicator) -> harfanglab.SigmaRule:
        """
        Create a Harfanglab Sigma rule based on an indicator.
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
        Create a Harfanglab Yara file based on an indicator.
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
    def _get_ioc_type(
        indicator: opencti.Indicator, observable: opencti.Observable
    ) -> str:
        """
        Get IOC rule type based on an OpenCTI observable referenced in indicator's STIX pattern.
        :param indicator: OpenCTI indicator referencing observable
        :param observable: OpenCTI observable referenced in indicator's STIX pattern
        :return: IOC rule type
        """
        ioc_type = None
        for observable_tuple in indicator.observables:
            object_path, indicator_observable = observable_tuple
            if indicator_observable.value == observable.value:
                if object_path:
                    ioc_type = IOC_TYPES_BY_OBJECT_PATH.get(object_path.lower())
                else:
                    if observable.entity_type.lower() == "stixfile":
                        ioc_type = (
                            "hash" if is_file_hash(observable.value) else "filename"
                        )
                    else:
                        ioc_type = IOC_TYPES_BY_ENTITY_TYPE.get(
                            observable.entity_type.lower()
                        )
                break
        return ioc_type
