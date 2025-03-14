"""Provide custom types for Pydantic models."""

import warnings
from enum import Enum
from typing import Annotated, Any, Callable

from pydantic import AfterValidator

import dragos.domain.models.octi.enums as octi_enums


def is_in_enum(enum: Enum) -> Callable:
    """Get validator to check if a value is in given enum."""

    def compare_value(value: Any) -> Any:
        """Check if value is in enum."""
        enum_values = [member.value for member in enum]
        if value not in enum_values:
            if issubclass(enum, octi_enums.OpenVocab):
                warnings.warn(
                    f"Value '{value}' out of recommended values: {', '.join(enum_values)}."
                )
            else:
                raise ValueError(
                    f"Invalid value '{value}'. Allowed values are: {', '.join(enum_values)}."
                )
        return value

    return compare_value


AccountType = Annotated[str, AfterValidator(is_in_enum(octi_enums.AccountType))]

AttackMotivation = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.AttackMotivation))
]

AttackResourceLevel = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.AttackResourceLevel))
]

CvssSeverity = Annotated[str, AfterValidator(is_in_enum(octi_enums.CvssSeverity))]

EncryptionAlgorithm = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.EncryptionAlgorithm))
]

HashAlgorithm = Annotated[str, AfterValidator(is_in_enum(octi_enums.HashAlgorithm))]

ImplementationLanguage = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.ImplementationLanguage))
]

IndicatorType = Annotated[str, AfterValidator(is_in_enum(octi_enums.IndicatorType))]

IndustrySector = Annotated[str, AfterValidator(is_in_enum(octi_enums.IndustrySector))]

LocationType = Annotated[str, AfterValidator(is_in_enum(octi_enums.LocationType))]

MalwareCapability = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.MalwareCapability))
]

MalwareType = Annotated[str, AfterValidator(is_in_enum(octi_enums.MalwareType))]

ObservableType = Annotated[str, AfterValidator(is_in_enum(octi_enums.ObservableType))]

OrganizationType = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.OrganizationType))
]

PatternType = Annotated[str, AfterValidator(is_in_enum(octi_enums.PatternType))]

Platform = Annotated[str, AfterValidator(is_in_enum(octi_enums.Platform))]

ProcessorArchitecture = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.ProcessorArchitecture))
]

Region = Annotated[str, AfterValidator(is_in_enum(octi_enums.Region))]

Reliability = Annotated[str, AfterValidator(is_in_enum(octi_enums.Reliability))]

ReportType = Annotated[str, AfterValidator(is_in_enum(octi_enums.ReportType))]

TLPLevel = Annotated[str, AfterValidator(is_in_enum(octi_enums.TLPLevel))]

WindowsRegistryDatatype = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.WindowsRegistryDatatype))
]

WindowsIntegrityLevel = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.WindowsIntegrityLevel))
]

WindowsServiceStartType = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.WindowsServiceStartType))
]

WindowsServiceStatus = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.WindowsServiceStatus))
]

WindowsServiceType = Annotated[
    str, AfterValidator(is_in_enum(octi_enums.WindowsServiceType))
]
