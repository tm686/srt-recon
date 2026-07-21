"""
Auto-scan: runs tools in a smart order based on project category.

Tool ordering logic:
- Each category has a pipeline of tools that make sense for it
- Tools run sequentially: next tool starts after previous completes
- Aggressiveness controls thread counts and tool selection depth
"""

from app.db.models import ProjectCategory

# Tool pipelines per project category (ordered: each step feeds the next)
PIPELINES: dict[str, list[dict]] = {
    ProjectCategory.wildcard_domain: [
        {"tool": "subfinder", "type": "subdomain_enum", "desc": "Passive subdomain discovery"},
        {"tool": "assetfinder", "type": "subdomain_enum", "desc": "Additional subdomain sources"},
        {"tool": "dnsx", "type": "dns_resolution", "desc": "DNS resolution + wildcard filtering"},
        {"tool": "httpx", "type": "live_hosts", "desc": "Probe live HTTP servers"},
        {"tool": "gau", "type": "url_crawl", "desc": "Historical URL collection"},
        {"tool": "katana", "type": "url_crawl", "desc": "Active crawling + JS parsing"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory brute-forcing"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.single_host: [
        {"tool": "httpx", "type": "live_hosts", "desc": "Probe host details"},
        {"tool": "katana", "type": "url_crawl", "desc": "Crawl + JS parsing"},
        {"tool": "gau", "type": "url_crawl", "desc": "Historical URLs"},
        {"tool": "waybackurls", "type": "url_crawl", "desc": "Wayback Machine URLs"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory brute-forcing"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.single_ip: [
        {"tool": "nmap", "type": "port_scan", "desc": "Port + service discovery"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.cidr_range: [
        {"tool": "nmap", "type": "port_scan", "desc": "Port scanning the range"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.ip_list: [
        {"tool": "nmap", "type": "port_scan", "desc": "Port + service discovery"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory brute-forcing"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
}

# Thread multipliers per aggressiveness level
THREAD_MULTIPLIERS = {
    "conservative": 0.5,
    "normal": 1.0,
    "aggressive": 2.5,
}

# Additional tools unlocked at aggressive level
AGGRESSIVE_EXTRAS: dict[str, list[dict]] = {
    ProjectCategory.wildcard_domain: [
        {"tool": "waybackurls", "type": "url_crawl", "desc": "Extra wayback URL scraping"},
    ],
    ProjectCategory.single_host: [],
    ProjectCategory.single_ip: [
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing on open ports"},
    ],
    ProjectCategory.cidr_range: [],
    ProjectCategory.ip_list: [],
}


def get_pipeline(category: str, aggressiveness: str = "normal") -> list[dict]:
    """Get the ordered tool pipeline for a project category."""
    pipeline = list(PIPELINES.get(category, PIPELINES[ProjectCategory.wildcard_domain]))

    if aggressiveness == "aggressive":
        extras = AGGRESSIVE_EXTRAS.get(category, [])
        # Insert extras before the final step (gowitness)
        insert_idx = len(pipeline) - 1
        for extra in extras:
            pipeline.insert(insert_idx, extra)
            insert_idx += 1

    if aggressiveness == "conservative":
        # Remove fuzzing tools in conservative mode
        pipeline = [t for t in pipeline if t["tool"] not in ("ffuf", "waybackurls")]

    return pipeline


def get_threads(base_threads: int, aggressiveness: str = "normal") -> int:
    """Get thread count adjusted for aggressiveness."""
    multiplier = THREAD_MULTIPLIERS.get(aggressiveness, 1.0)
    return max(1, int(base_threads * multiplier))


def get_tools_for_category(category: str) -> list[str]:
    """Get list of tool names relevant to a project category."""
    pipeline = PIPELINES.get(category, PIPELINES[ProjectCategory.wildcard_domain])
    return [step["tool"] for step in pipeline]


# ── Quick Scan pipelines (fast, reduced tool set) ────────────────────

QUICK_PIPELINES: dict[str, list[dict]] = {
    ProjectCategory.wildcard_domain: [
        {"tool": "subfinder", "type": "subdomain_enum", "desc": "Passive subdomain discovery"},
        {"tool": "httpx", "type": "live_hosts", "desc": "Probe live HTTP servers"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (small wordlist)"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.single_host: [
        {"tool": "httpx", "type": "live_hosts", "desc": "Probe host details"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (small wordlist)"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scan (high+critical)"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.single_ip: [
        {"tool": "nmap", "type": "port_scan", "desc": "Port scan (top 100)"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scan (high+critical)"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.cidr_range: [
        {"tool": "nmap", "type": "port_scan", "desc": "Port scan (top 100)"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.ip_list: [
        {"tool": "nmap", "type": "port_scan", "desc": "Port scan (top 100)"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Vulnerability scan (high+critical)"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
}


def get_quick_pipeline(category: str) -> list[dict]:
    """Get the reduced quick-scan pipeline for a project category."""
    return list(QUICK_PIPELINES.get(category, QUICK_PIPELINES[ProjectCategory.wildcard_domain]))


# ── Deep Scan pipelines (thorough, long wordlists, all tools) ────────

DEEP_PIPELINES: dict[str, list[dict]] = {
    ProjectCategory.wildcard_domain: [
        {"tool": "subfinder", "type": "subdomain_enum", "desc": "Passive subdomain discovery"},
        {"tool": "assetfinder", "type": "subdomain_enum", "desc": "Additional subdomain sources"},
        {"tool": "alterx", "type": "subdomain_enum", "desc": "Subdomain permutation wordlists"},
        {"tool": "dnsx", "type": "dns_resolution", "desc": "DNS resolution + wildcard filtering"},
        {"tool": "httpx", "type": "live_hosts", "desc": "Probe live HTTP servers"},
        {"tool": "gau", "type": "url_crawl", "desc": "Historical URL collection"},
        {"tool": "katana", "type": "url_crawl", "desc": "Active crawling + JS parsing"},
        {"tool": "waybackurls", "type": "url_crawl", "desc": "Wayback Machine URLs"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (long wordlist)"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Full vulnerability scanning"},
        {"tool": "dalfox", "type": "vuln_scan", "desc": "XSS vulnerability scanning"},
        {"tool": "subjack", "type": "vuln_scan", "desc": "Subdomain takeover checking"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.single_host: [
        {"tool": "httpx", "type": "live_hosts", "desc": "Probe host details"},
        {"tool": "katana", "type": "url_crawl", "desc": "Deep crawl + JS parsing"},
        {"tool": "gau", "type": "url_crawl", "desc": "Historical URLs"},
        {"tool": "waybackurls", "type": "url_crawl", "desc": "Wayback Machine URLs"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (long wordlist)"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Full vulnerability scanning"},
        {"tool": "dalfox", "type": "vuln_scan", "desc": "XSS vulnerability scanning"},
        {"tool": "subjack", "type": "vuln_scan", "desc": "Subdomain takeover checking"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.single_ip: [
        {"tool": "nmap", "type": "port_scan", "desc": "Full port scan (all ports)"},
        {"tool": "rustscan", "type": "port_scan", "desc": "Fast port scanning"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (long wordlist)"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Full vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.cidr_range: [
        {"tool": "nmap", "type": "port_scan", "desc": "Full port scan (all ports)"},
        {"tool": "rustscan", "type": "port_scan", "desc": "Fast port scanning"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (long wordlist)"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Full vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
    ProjectCategory.ip_list: [
        {"tool": "nmap", "type": "port_scan", "desc": "Full port scan (all ports)"},
        {"tool": "rustscan", "type": "port_scan", "desc": "Fast port scanning"},
        {"tool": "httpx", "type": "live_hosts", "desc": "HTTP service detection"},
        {"tool": "ffuf", "type": "dir_fuzz", "desc": "Directory fuzzing (long wordlist)"},
        {"tool": "nuclei", "type": "vuln_scan", "desc": "Full vulnerability scanning"},
        {"tool": "gowitness", "type": "screenshot", "desc": "Capture screenshots of live hosts"},
    ],
}


def get_deep_pipeline(category: str) -> list[dict]:
    """Get the thorough deep-scan pipeline for a project category."""
    return list(DEEP_PIPELINES.get(category, DEEP_PIPELINES[ProjectCategory.wildcard_domain]))
