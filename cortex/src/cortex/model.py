# -*- coding: utf-8 -*-
"""OpenCTI Cortex connector models."""

from datetime import datetime
from pydantic import BaseModel, Field


class CortexJob(BaseModel):
    id: str
    analyzer_definition_id: str = Field(alias="analyzerDefinitionId")
    analyzer_id: str = Field(alias="analyzerId")
    analyzer_name: str = Field(alias="analyzerName")
    status: str
    data: str = None
    parameters: dict
    tlp: int
    attachment: dict = None
    message: str
    dataType: str
    organization: str
    start_date: datetime = Field(alias="startDate")
    end_date: datetime = Field(alias="endDate")
    date: datetime
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")
    updated_by: str = Field(alias="updatedBy")


class CortexAnalyzer(BaseModel):
    name: str
    description: str
    data_type_list = list = Field(alias="dataTypeList")
    analyzer_definition_id: str = Field(alias="analyzerDefinitionId")
    job_timeout: int = Field(alias="jobTimeout")
    rate: int
    rate_unit: str = Field(alias="rateUnit")
