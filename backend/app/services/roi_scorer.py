"""
ROI (Return on Investment) scoring for consolidated endpoints.
Prioritizes which endpoints are worth investigating based on metadata signals.
"""

import re

# CMS / API framework keywords that boost score
_CMS_KEYWORDS = {"wordpress", "drupal", "joomla", "magento", "wp-"}
_API_KEYWORDS = {"graphql", "swagger", "openapi", "api-docs"}
_NON_STANDARD_PORTS = {8080, 8443, 3000, 5000, 9090, 8000, 8888, 4443, 9443}

# Version pattern in Server header (e.g. "Apache/2.4.51", "nginx/1.21.3")
_VERSION_RE = re.compile(r"/\d+\.\d+")


def calculate_roi_score(
    value: str,
    result_type: str,
    metadata: dict,
    scan_count: int,
    vuln_count: int = 0,
) -> tuple[int, str]:
    """Calculate ROI score for a consolidated endpoint.

    Returns (score, priority) where priority is "critical"|"high"|"medium"|"low".
    """
    score = 0

    # ── Status code signals ──
    status_code = metadata.get("status_code")
    if status_code:
        if 200 <= status_code < 300:
            score += 15
        elif status_code in (401, 403):
            score += 10
        elif 300 <= status_code < 400 or 500 <= status_code < 600:
            score += 5

    # ── Technology signals ──
    tech = metadata.get("tech", [])
    if isinstance(tech, list):
        # +2 per tech, max 20
        score += min(len(tech) * 2, 20)

        tech_lower = {t.lower() for t in tech}
        # CMS detection
        if any(kw in t for t in tech_lower for kw in _CMS_KEYWORDS):
            score += 15
        # API framework detection
        if any(kw in t for t in tech_lower for kw in _API_KEYWORDS):
            score += 15

    # ── Input signals ──
    if "?" in value:
        score += 5

    # ── Infrastructure signals ──
    try:
        # Extract port from URL or host:port
        if "://" in value:
            host_part = value.split("://", 1)[1].split("/", 1)[0]
        else:
            host_part = value.split("/", 1)[0]

        if ":" in host_part:
            port_str = host_part.rsplit(":", 1)[1]
            port = int(port_str)
            if port in _NON_STANDARD_PORTS:
                score += 10
    except (ValueError, IndexError):
        pass

    # ── Vulnerability signals ──
    score += vuln_count * 20

    # ── Multi-tool corroboration ──
    if scan_count > 1:
        score += (scan_count - 1) * 5

    # ── Server header version disclosure ──
    server = metadata.get("server", "")
    if server and _VERSION_RE.search(server):
        score += 5

    # ── Priority classification ──
    if score >= 100:
        priority = "critical"
    elif score >= 60:
        priority = "high"
    elif score >= 30:
        priority = "medium"
    else:
        priority = "low"

    return score, priority
