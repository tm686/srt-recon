import shutil
from pathlib import Path

from app.schemas.settings import ToolStatus

TOOLS = [
    "subfinder",
    "dnsx",
    "httpx",
    "nuclei",
    "gau",
    "katana",
    "dalfox",
    "subjack",
    "ffuf",
    "nmap",
    "waybackurls",
    "assetfinder",
    "gowitness",
    "rustscan",
    "alterx",
    "notify",
]


def check_tools(extra_paths: list[str] | None = None) -> list[ToolStatus]:
    results = []
    for name in TOOLS:
        path = None
        # Check extra_paths first so Go binaries take priority
        if extra_paths:
            for ep in extra_paths:
                candidate = Path(ep) / name
                if candidate.is_file():
                    path = str(candidate)
                    break
        if not path:
            path = shutil.which(name)
        results.append(ToolStatus(name=name, installed=path is not None, path=path))
    return results
