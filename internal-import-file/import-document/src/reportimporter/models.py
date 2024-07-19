import json
import os
import re
from json import JSONDecodeError
from typing import Any, Dict, List, Optional, Pattern

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
        return list(filter(None, (x.strip() for x in field.splitlines())))

    def _load_regex_pattern(self, regex_values: List[str]) -> List[Pattern]:
        regexes = []
        if len(regex_values) == 0:
            return []

        for regex_value in regex_values:
            try:
                compiled_re = re.compile(regex_value, re.IGNORECASE)
                regexes.append(compiled_re)
            except re.error as e:
                raise ValueError(
                    f"Observable {self.name}: Unable to create regex from value '{regex_value}' ({e})"
                )

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
    omit_match_in: List[str] = []


class EntityConfig(BaseModel):
    name: str
    stix_class: str
    filter: Optional[Dict]
    fields: List[str]
    exact_match_fields: List[str] = []
    exclude_values: List[str] = []
    regex: List[Pattern] = []
    omit_match_in: List[str] = []
    custom_attributes: str

    @validator(
        "fields", "exact_match_fields", "exclude_values", "omit_match_in", pre=True
    )
    def pre_validate_transform_str_to_list(cls, field: str) -> List[str]:
        return list(filter(None, (x.strip() for x in field.splitlines())))

    @validator("filter", pre=True)
    def pre_validate_transform_str_to_json(cls, filter_string: str) -> Any:
        try:
            return json.loads(filter_string)
        except JSONDecodeError as e:
            raise ValueError(f"filter received an invalid json string: {e}")

    def convert_to_entity(
        self, opencti_response: List[Dict], helper: OpenCTIConnectorHelper
    ) -> List[Entity]:
        entities = []
        for item in opencti_response:
            _id = item.get("standard_id")
            item_values = set()
            exact_match_values = set()

            for relevant_field in self.fields:
                elem = item.get(relevant_field, None)
                if elem:
                    if type(elem) == list:
                        item_values.update(elem)
                        if relevant_field in self.exact_match_fields:
                            exact_match_values.update(elem)
                    elif type(elem) == str:
                        item_values.add(elem)
                        if relevant_field in self.exact_match_fields:
                            exact_match_values.add(elem)

            indicators = []
            for value in item_values:
                # Remove SDO names which are defined to be excluded in the entity config
                if value.lower() in self.exclude_values:
                    helper.log_debug(
                        f"Entity: Discarding value '{value}' due to explicit exclusion as defined in {self.exclude_values}"
                    )
                    continue

                ignore_case_value = True
                if value in exact_match_values:
                    ignore_case_value = False

                value = re.escape(value)
                value = f"\\b{value}\\b"
                try:
                    if ignore_case_value:
                        compiled_re = re.compile(value, re.IGNORECASE)
                    else:
                        compiled_re = re.compile(value)
                    indicators.append(compiled_re)
                except re.error as e:
                    helper.log_error(
                        f"Entity {self.name}: Unable to create regex from value '{value}' ({e})"
                    )

            if len(indicators) == 0:
                continue

            entity = Entity(
                name=self.name,
                stix_class=self.stix_class,
                stix_id=_id,
                values=item_values,
                regex=indicators,
                omit_match_in=self.omit_match_in,
            )
            entities.append(entity)

        return entities
