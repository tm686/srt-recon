from datetime import datetime

from pydantic import BaseModel, Field


class ApiKeyCreate(BaseModel):
    provider: str = Field(min_length=1, max_length=100)
    key: str = Field(min_length=1)


class ApiKeyUpdate(BaseModel):
    provider: str | None = None
    key: str | None = None


class ApiKeyOut(BaseModel):
    id: int
    project_id: int
    provider: str
    masked_key: str
    is_valid: bool
    last_tested_at: datetime | None = None

    model_config = {"from_attributes": True}


class ApiKeyTestResult(BaseModel):
    id: int
    provider: str
    is_valid: bool
    message: str
