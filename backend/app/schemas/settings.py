from pydantic import BaseModel, Field


class SetupRequest(BaseModel):
    password: str = Field(min_length=12)
    confirm_password: str = Field(min_length=12)


class UnlockRequest(BaseModel):
    password: str


class SettingsOut(BaseModel):
    seclists_path: str = "/usr/share/seclists"
    go_tools_path: str = ""
    default_threads: int = 10
    aggressiveness: str = "normal"  # conservative, normal, aggressive
    wordlist_ffuf: str = ""
    setup_complete: bool = False


class SettingsUpdate(BaseModel):
    seclists_path: str | None = None
    go_tools_path: str | None = None
    default_threads: int | None = None
    aggressiveness: str | None = None
    wordlist_ffuf: str | None = None


class WordlistOption(BaseModel):
    name: str
    path: str
    size_kb: float
    source: str


class PathValidateRequest(BaseModel):
    path: str


class PathValidateResponse(BaseModel):
    path: str
    exists: bool
    is_directory: bool


class ToolStatus(BaseModel):
    name: str
    installed: bool
    path: str | None = None


class SetupStatusResponse(BaseModel):
    setup_complete: bool
    vault_unlocked: bool
