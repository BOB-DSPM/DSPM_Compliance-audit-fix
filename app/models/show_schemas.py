# app/models/show_schemas.py
from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel

class FrameworkCountOut(BaseModel):
    framework: str
    count: int

class RequirementRowOut(BaseModel):
    id: int
    item_code: Optional[str] = None
    title: str
    mapping_status: Optional[str] = None

class MappingOut(BaseModel):
    code: str
    category: Optional[str] = None
    service: Optional[str] = None
    console_path: Optional[str] = None
    check_how: Optional[str] = None
    cli_cmd: Optional[str] = None
    return_field: Optional[str] = None
    compliant_value: Optional[str] = None
    non_compliant_value: Optional[str] = None
    console_fix: Optional[str] = None
    cli_fix_cmd: Optional[str] = None

class RequirementDetailOut(BaseModel):
    framework: str
    requirement: RequirementRowOut
    mappings: List[MappingOut]
