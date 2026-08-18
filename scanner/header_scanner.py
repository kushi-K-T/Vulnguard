import requests

class HeaderScanner:
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "Medium",
            "impact": "Absence permits broad cross-site scripting and unauthorized content injection.",
            "recommendation": "Define a strict CSP: default-src 'self';"
        },
        "X-Frame-Options": {
            "severity": "Medium",
            "impact": "Allows the web page to be framed, introducing Clickjacking risks.",
            "recommendation": "Configure X-Frame-Options: DENY or SAMEORIGIN."
        },
        "X-Content-Type-Options": {
            "severity": "Low",
            "impact": "Allows browsers to perform MIME-type sniffing on loaded resources.",
            "recommendation": "Set X-Content-Type-Options: nosniff."
        },
        "Strict-Transport-Security": {
            "severity": "Low",
            "impact": "Connections may be vulnerable to SSL stripping attacks on unencrypted links.",
            "recommendation": "Enable HSTS: max-age=31536000; includeSubDomains."
        },
        "Referrer-Policy": {
            "severity": "Low",
            "impact": "May expose sensitive URLs and query parameters to third-party endpoints.",
            "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin."
        }
    }

    @classmethod
    def scan(cls, target_url: str, response: requests.Response) -> list[dict]:
        findings = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, meta in cls.SECURITY_HEADERS.items():
            if header_name.lower() not in headers:
                findings.append({
                    "id": f"HDR-{header_name[:4].upper()}",
                    "title": f"Missing Security Header: {header_name}",
                    "category": "Security Misconfiguration",
                    "severity": meta["severity"],
                    "evidence": f"Header '{header_name}' was not returned by {target_url}",
                    "description": f"The HTTP response lacks the {header_name} protection directive.",
                    "impact": meta["impact"],
                    "recommendation": meta["recommendation"],
                    "status": "Open"
                })
        return findings
