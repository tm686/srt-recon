import httpx


async def test_api_key(provider: str, key: str) -> tuple[bool, str]:
    """Test an API key against the provider's endpoint. Returns (is_valid, message)."""
    testers = {
        "securitytrails": _test_securitytrails,
        "shodan": _test_shodan,
        "censys": _test_censys,
        "github": _test_github,
        "virustotal": _test_virustotal,
        "chaos": _test_chaos,
    }

    tester = testers.get(provider.lower())
    if not tester:
        return False, f"Unknown provider: {provider}"

    try:
        return await tester(key)
    except httpx.HTTPError as e:
        return False, f"Connection error: {e}"
    except Exception as e:
        return False, f"Test failed: {e}"


async def _test_securitytrails(key: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://api.securitytrails.com/v1/ping",
            headers={"APIKEY": key},
        )
    if r.status_code == 200:
        return True, "SecurityTrails API key is valid"
    return False, f"Invalid key (HTTP {r.status_code})"


async def _test_shodan(key: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"https://api.shodan.io/api-info?key={key}")
    if r.status_code == 200:
        return True, "Shodan API key is valid"
    return False, f"Invalid key (HTTP {r.status_code})"


async def _test_censys(key: str) -> tuple[bool, str]:
    # Censys keys are "id:secret" format
    parts = key.split(":", 1)
    if len(parts) != 2:
        return False, "Censys key must be in 'id:secret' format"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://search.censys.io/api/v1/account",
            auth=(parts[0], parts[1]),
        )
    if r.status_code == 200:
        return True, "Censys API key is valid"
    return False, f"Invalid key (HTTP {r.status_code})"


async def _test_github(key: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {key}"},
        )
    if r.status_code == 200:
        return True, "GitHub token is valid"
    return False, f"Invalid token (HTTP {r.status_code})"


async def _test_virustotal(key: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://www.virustotal.com/api/v3/users/me",
            headers={"x-apikey": key},
        )
    if r.status_code == 200:
        return True, "VirusTotal API key is valid"
    return False, f"Invalid key (HTTP {r.status_code})"


async def _test_chaos(key: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://dns.projectdiscovery.io/dns/example.com/subdomains",
            headers={"Authorization": key},
        )
    if r.status_code in (200, 404):
        return True, "Chaos API key is valid"
    return False, f"Invalid key (HTTP {r.status_code})"
