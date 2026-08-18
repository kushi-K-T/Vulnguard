import requests
from urllib.parse import urljoin

class SafeOWASPScanner:
    """Safe, non-destructive educational checks for OWASP Top 10 indicators."""

    DISCLOSURE_PATHS = [
        "/.git/HEAD",
        "/robots.txt",
        "/server-status",
        "/phpinfo.php",
        "/.env"
    ]

    @classmethod
    def scan_misconfigurations(cls, base_url: str) -> list[dict]:
        findings = []
        for path in cls.DISCLOSURE_PATHS:
            target = urljoin(base_url, path)
            try:
                res = requests.get(target, timeout=2.0, allow_redirects=False)
                if res.status_code == 200:
                    severity = "High" if path in {"/.git/HEAD", "/.env"} else "Informational"
                    findings.append({
                        "id": f"OWASP-A05-{path.replace('/', '_').replace('.', '')}",
                        "title": f"Potentially Sensitive File Disclosed: {path}",
                        "category": "A05: Security Misconfiguration",
                        "severity": severity,
                        "evidence": f"HTTP 200 OK received at {target}",
                        "description": f"The path {path} is publicly accessible without authentication.",
                        "impact": "Exposure of application internals, metadata, or source control pointers.",
                        "recommendation": f"Restrict public access to {path} in web server configuration.",
                        "status": "Open"
                    })
            except requests.RequestException:
                continue
        return findings

    @classmethod
    def scan_debug_indicators(cls, response: requests.Response) -> list[dict]:
        findings = []
        text = response.text.lower()
        debug_indicators = ["stack trace:", "traceback (most recent call last):", "exception in thread", "fatal error:"]
        for indicator in debug_indicators:
            if indicator in text:
                findings.append({
                    "id": "OWASP-A05-DEBUG",
                    "title": "Verbose Debug/Error Stack Trace Exposed",
                    "category": "A05: Security Misconfiguration",
                    "severity": "Medium",
                    "evidence": f"Page content contains runtime keyword: '{indicator}'",
                    "description": "Application displays raw stack traces directly in HTTP responses.",
                    "impact": "Aids reverse engineering and framework vulnerability identification.",
                    "recommendation": "Disable debug mode in production and configure generic error handling.",
                    "status": "Open"
                })
                break
        return findings
