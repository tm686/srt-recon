from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import ProjectCategory, ScopeDirection, TargetType


class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=512)
    target_type: TargetType
    direction: ScopeDirection = ScopeDirection.in_scope


class TargetUpdate(BaseModel):
    value: str | None = None
    target_type: TargetType | None = None
    direction: ScopeDirection | None = None


class TargetOut(BaseModel):
    id: int
    project_id: int
    value: str
    target_type: TargetType
    direction: ScopeDirection

    model_config = {"from_attributes": True}


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    category: ProjectCategory = ProjectCategory.wildcard_domain
    target_value: str = ""  # the primary target


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class ProjectOut(BaseModel):
    id: int
    name: str
    description: str
    category: ProjectCategory
    target_value: str
    created_at: datetime
    updated_at: datetime
    targets: list[TargetOut] = []

    model_config = {"from_attributes": True}


class ProjectListOut(BaseModel):
    id: int
    name: str
    description: str
    category: ProjectCategory
    target_value: str
    created_at: datetime
    updated_at: datetime
    target_count: int = 0

    model_config = {"from_attributes": True}


class ScopeValidateRequest(BaseModel):
    values: list[str]


class ScopeValidateResponse(BaseModel):
    in_scope: list[str]
    out_of_scope: list[str]
