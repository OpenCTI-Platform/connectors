from .stix_adapter_compromised_mixin import CompromisedMixin
from .stix_adapter_core_mixin import AdapterCoreMixin
from .stix_adapter_malware_mixin import MalwareMixin
from .stix_adapter_osi_hi_mixin import OsiHiMixin
from .stix_adapter_sdo_mixin import SdoMixin
from .stix_adapter_special_mixin import StixAdapterSpecialMixin


class DataToSTIXAdapter(
    StixAdapterSpecialMixin,
    CompromisedMixin,
    OsiHiMixin,
    MalwareMixin,
    SdoMixin,
    AdapterCoreMixin,
):
    pass
