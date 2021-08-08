import json
import os
import re
import ioc_finder.data
from typing import List, Optional, Dict, Pattern, Any
from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel, validator
from reportimporter.constants import (
    COMMENT_INDICATOR,
    CONFIG_PATH,
    OBSERVABLE_DETECTION_CUSTOM_REGEX,
    OBSERVABLE_DETECTION_OPTIONS,
)


class Observable(BaseModel):
    name: str
    detection_option: str

    # Custom Regex approach
    regex_patterns: List[str] = []
    regex: List[Pattern] = []

    # Further processing
    defang: bool = False
    stix_target: str

    # Whitelisting options
    filter_config: List[str] = []
    filter_regex: List[Pattern] = []

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.detection_option == OBSERVABLE_DETECTION_CUSTOM_REGEX:
            self.regex = self._load_regex_pattern(self.regex_patterns)

        self.filter_regex = self._load_filter_values(self.filter_config)

    @validator("detection_option")
    def validate_detection_value(cls, value: str) -> str:
        if value not in OBSERVABLE_DETECTION_OPTIONS:
            raise ValueError("{} is not a valid detection_option value")
        return value

    @validator("filter_config")
    def validate_files_exist(cls, filter_config: List[str]) -> List[str]:
        if len(filter_config) == 0:
            return filter_config

        filter_paths = []
        for filter_file in filter_config:
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_path, CONFIG_PATH, filter_file)
            if not os.path.isfile(file_path):
                raise ValueError(
                    "{} is not a valid filter config file".format(file_path)
                )

            filter_paths.append(file_path)
        return filter_paths

    @validator("regex_patterns", "filter_config", pre=True)
    def pre_validate_transform_str_to_list(cls, field: str) -> Any:
        if isinstance(field, str):
            return list(filter(None, (x.strip() for x in field.splitlines())))
        return field

    @staticmethod
    def _load_regex_pattern(regex_values: List[str]) -> List[Pattern]:
        regexes = []
        if len(regex_values) == 0:
            return []

        for regex_value in regex_values:
            regexes.append(re.compile(regex_value, re.IGNORECASE))

        return regexes

    def _load_filter_values(self, filter_config_paths: List[str]) -> List[Pattern]:
        if len(filter_config_paths) == 0:
            return []

        filter_patterns = []
        for filter_file in filter_config_paths:
            with open(filter_file, "r") as f:
                for line in f:
                    line = line.strip()

                    if len(line) == 0 or line.startswith(COMMENT_INDICATOR):
                        continue

                    filter_patterns.append("\\b{}\\b".format(line))

        filter_patterns = self._load_regex_pattern(filter_patterns)
        return filter_patterns


class Entity(BaseModel):
    name: str
    stix_class: str
    stix_id: str
    values: List[str]
    regex: List[Pattern] = []


class EntityConfig(BaseModel):
    name: str
    stix_class: str
    filter: Optional[Dict]
    fields: List[str]
    exclude: List[str] = []
    regex: List[Pattern] = []

    @validator("fields", "exclude", pre=True)
    def pre_validate_transform_str_to_list(cls, field: str) -> Any:
        if isinstance(field, str):
            return list(filter(None, (x.strip() for x in field.splitlines())))
        return field

    @validator("filter", pre=True)
    def pre_validate_transform_str_to_json(cls, filter: str) -> Any:
        if isinstance(filter, str):
            return json.loads(filter)
        return filter

    def convert_to_entity(
        self, opencti_response: List, helper: OpenCTIConnectorHelper
    ) -> List[Entity]:
        entities = []
        for item in opencti_response:
            _id = item.get("standard_id")
            item_values = set()
            if (
                item.get("externalReferences", None) is None
                or len(item["externalReferences"]) == 0
            ):
                continue

            for relevant_field in self.fields:
                elem = item.get(relevant_field, [])
                if elem:
                    if type(elem) == list:
                        item_values.update(elem)
                    elif type(elem) == str:
                        item_values.add(elem)

            # Exclude certain SDO names which are too generic for being used to automatically parse text
            indicators = []
            for value in item_values:
                # Approach 1: Remove SDO names which are also TLDs
                if value.lower() in ioc_finder.data.tlds:
                    helper.log_debug(
                        f"Entity: Discarding value '{value}' due to TLD match"
                    )
                    continue

                # Approach 2: Remove SDO names which are defined to be excluded in the entity config
                if value.lower() in self.exclude:
                    helper.log_debug(
                        f"Entity: Discarding value '{value}' due to explicit exclusion"
                    )
                    continue

                indicators.append(f"\\b{value}\\b")

            indicators = "|".join(indicators)
            regex = re.compile(indicators, re.IGNORECASE)

            entity = Entity(
                name=self.name,
                stix_class=self.stix_class,
                stix_id=_id,
                values=item_values,
                regex=[regex],
            )
            entities.append(entity)

        return entities
