from datetime import datetime
from pydantic import BaseModel


class ScanCreate(BaseModel):
    scan_type: str  # subdomain_enum, live_hosts, url_crawl, port_scan, dir_fuzz, vuln_scan
    tool_name: str  # subfinder, httpx, gau, katana, nmap, ffuf, nuclei, etc.
    target_override: str | None = None  # optional: override project scope with specific target
    options: dict = {}  # tool-specific flags: threads, wordlist, ports, etc.


class ScanOut(BaseModel):
    id: int
    project_id: int
    scan_type: str
    status: str
    tool_name: str
    command: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    result_count: int = 0

    model_config = {"from_attributes": True}


class ScanResultOut(BaseModel):
    id: int
    scan_id: int
    result_type: str
    value: str
    metadata_json: str

    model_config = {"from_attributes": True}


class ScanListOut(BaseModel):
    scans: list[ScanOut]
    running_count: int


class ScanLaunchConfig(BaseModel):
    """Optional configuration for quick/auto/deep scan launches."""
    ports: str | None = None  # e.g. "80,443", "1-1000", "--top-ports 100"
    scan_speed: str = "normal"  # "stealth" | "normal" | "aggressive"


class CustomToolConfig(BaseModel):
    """Configuration for a single tool in a custom scan."""
    tool_name: str
    scan_type: str
    options: dict = {}


class CustomScanRequest(BaseModel):
    """Request body for launching a custom scan pipeline."""
    tools: list[CustomToolConfig]
    target_override: str | None = None
    scan_speed: str = "normal"
    ports: str | None = None
