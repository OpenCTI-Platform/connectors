# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector models."""

from datetime import date
from typing import List, Optional

from pydantic import BaseModel


class MalpediaModels:

    @staticmethod
    def create_family_model():
        class Family(BaseModel):
            """Malpedia Family model."""

            malpedia_name: Optional[str]
            updated: Optional[date] = date.today()
            library_entries: Optional[list]
            attribution: Optional[list]
            description: Optional[str]
            notes: Optional[list]
            alt_names: Optional[list]
            sources: Optional[list]
            urls: List[str]
            common_name: Optional[str]
            uuid: str

            @property
            def malpedia_url(self) -> str:
                """Malpedia URL."""
                return f"https://malpedia.caad.fkie.fraunhofer.de/details/{self.malpedia_name}"

            @property
            def malpedia_aliases(self) -> list:
                """Malpedia aliases list."""
                return self.alt_names + [self.malpedia_name]

            @property
            def main_name(self) -> str:
                """Malpedia names list."""
                if self.common_name == "":
                    return self.malpedia_name
                return self.common_name

        return Family

    @staticmethod
    def create_malware_model():
        class Malware(BaseModel):
            """Malpedia Malware model."""

            name: str
            description: str
            aliases: list
            external_references: list
            object_marking_refs: list

        return Malware

    @staticmethod
    def create_yara_rule_model():
        class YaraRule(BaseModel):
            """Malpedia Yara Rule model."""

            name: str
            description: str
            pattern: str
            pattern_type: str
            object_marking_refs: list

        return YaraRule

    @staticmethod
    def create_observable_sample_model():
        class ObservableFile(BaseModel):
            """Malpedia Observable File model."""

            name: str
            hashes: dict[str, str]
            object_marking_refs: list

        return ObservableFile

    @staticmethod
    def create_indicator_sample_model():
        class IndicatorSample(BaseModel):
            """Malpedia Indicator model."""

            name: str
            description: str
            pattern: str
            pattern_type: str
            object_marking_refs: list

        return IndicatorSample

    @staticmethod
    def create_intrusion_set_model():
        class IntrusionSet(BaseModel):
            """Malpedia intrusion set model."""

            name: str
            description: str
            aliases: list
            primary_motivation: str
            secondary_motivations: list
            external_references: list
            object_marking_refs: list

        return IntrusionSet
