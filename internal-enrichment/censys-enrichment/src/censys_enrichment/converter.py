from typing import Optional

from pydantic import BaseModel, Field


class OrganizationAuthor(BaseModel):
    abc_var: Optional[str] = Field(default=None)
    var: str


if __name__ == "__main__":
    OrganizationAuthor(var="test")
