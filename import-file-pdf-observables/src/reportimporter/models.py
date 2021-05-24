import json
import os
import re
from typing import List, Optional, Dict, Pattern, Any
from pydantic import BaseModel, validator
from reportimporter.constants import COMMENT_INDICATOR, PATH_TRAVERSAL, CONFIG_PATH


class Observable(BaseModel):
    name: str
    regex_patterns: List[str]
    regex: List[Pattern] = []
    defang: bool = False
    stix_target: str
    filter_config: List[str] = []
    filter_regex: List[Pattern] = []

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self.regex = self._load_regex_pattern(self.regex_patterns)
        self.filter_regex = self._load_filter_values(self.filter_config)

    @validator("filter_config")
    def config_file_exists(cls, filter_config: List[str]) -> List[str]:
        if len(filter_config) == 0:
            return filter_config

        filter_paths = []
        for filter_file in filter_config:
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(
                base_path, CONFIG_PATH, filter_file
            )
            if not os.path.isfile(file_path):
                raise ValueError(
                    "{} is not a valid filter config file".format(file_path)
                )

            filter_paths.append(file_path)
        return filter_paths

    @validator("regex_patterns", "filter_config", pre=True)
    def split_lines(cls, field: str) -> Any:
        if isinstance(field, str):
            return list(filter(None, (x.strip() for x in field.splitlines())))
        return field

    def _load_regex_pattern(self, regex_values: List[str]) -> List[Pattern]:
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
    def split_lines(cls, field: str) -> Any:
        if isinstance(field, str):
            return list(filter(None, (x.strip() for x in field.splitlines())))
        return field

    @validator("filter", pre=True)
    def convert_dict(cls, filter: str) -> Any:
        if isinstance(filter, str):
            return json.loads(filter)
        return filter

    def convert_to_entity(self, opencti_response: List) -> List[Entity]:
        """
        TODO

        :param opencti_response:
        :return:
        """
        entities = []
        for item in opencti_response:
            _id = item.get("id")
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

            # Continue if exclude value is present
            if set(self.exclude) & item_values:
                print("Name {} exclude {}".format(self.name, self.exclude))
                continue

            indicators = ["\\b{}\\b".format(v) for v in item_values]
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
