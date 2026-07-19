from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    app_name: str = "SRT-Recon"
    debug: bool = False
    database_url: str = "sqlite+aiosqlite:///./srt_recon.db"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    seclists_path: str = "/usr/share/seclists"
    go_tools_path: str = str(Path.home() / "go" / "bin")
    default_threads: int = 10

    model_config = {"env_prefix": "SRT_"}


settings = Settings()
