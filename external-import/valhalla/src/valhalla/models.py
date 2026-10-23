"""OpenCTI Valhalla connector models."""

import re
from datetime import datetime
from typing import List

from pydantic.v1 import BaseModel

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_IMPORT_DIRECTIVE = re.compile(r'^\s*import\s+"([^"]+)"', re.MULTILINE)


class Status(BaseModel):
    """Valhalla API Status model"""

    error: str
    num_rules: int
    status: str
    version: int


class YaraRule(BaseModel):
    """Valhalla YaraRule model"""

    author: str
    content: str
    date: str
    description: str
    minimum_yara: str
    name: str
    reference: str
    required_modules: list
    rule_hash: str
    score: int
    tags: list

    @property
    def cti_date(self) -> datetime:
        # Valhalla date format: 2020-04-27 13:28:41
        return datetime.strptime(self.date, "%Y-%m-%d %H:%M:%S")
        # return d.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    @property
    def cti_description(self) -> str:
        return (
            f"{self.description}\n\n"
            f"Minimum Yara version: {self.minimum_yara}\n\n"
            f"Required Yara modules: {', '.join(self.required_modules)}"
        )

    @property
    def cti_pattern(self) -> str:
        """
        YARA rule content preceded by the `import` statements it requires.

        Valhalla serves each rule without its `import` statements and lists the
        modules in `required_modules` instead (its own client writes them in the
        ruleset header), but an indicator pattern has to compile on its own. A
        module the content already imports is not imported again, so that its
        pattern, hence its indicator ID, stays the same.

        Returns:
            The rule content, unchanged when no import is missing
        """
        code = _BLOCK_COMMENT.sub("", self.content)
        imported = set(_IMPORT_DIRECTIVE.findall(code))
        imports = [
            f'import "{module}"'
            for module in dict.fromkeys(self.required_modules)
            if module not in imported
        ]
        if not imports:
            return self.content
        return "\n".join(imports) + "\n\n" + self.content


class ApiResponse(BaseModel):
    """Valhalla API Respose model"""

    api_version: str
    copyright: str
    customer: str
    date: str
    legal_note: str
    title: str
    rules: List[YaraRule]

    @property
    def cti_date(self) -> datetime:
        # Valhalla date format: 2020-04-27 13:28:41
        return datetime.strptime(self.date, "%Y-%m-%d %H:%M:%S")
        # return d.strftime("%Y-%m-%dT%H:%M:%S+00:00")


class ExternalReference(BaseModel):
    external_id: str | None = None


class StixObjects(BaseModel):
    type: str
    id: str
    external_references: List[ExternalReference] | None = None


class StixEnterpriseAttack(BaseModel):
    type: str
    id: str
    objects: List[StixObjects]
