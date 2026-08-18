import requests

class CookieScanner:
    @staticmethod
    def scan(target_url: str, response: requests.Response) -> list[dict]:
        findings = []
        cookies = response.cookies

        for cookie in cookies:
            cookie_name = cookie.name
            is_secure = cookie.secure
            is_httponly = cookie.has_nonstandard_attr("HttpOnly") or "httponly" in [k.lower() for k in cookie._rest.keys()]

            if not is_httponly:
                findings.append({
                    "id": f"CK-HTTPONLY-{cookie_name}",
                    "title": f"Missing HttpOnly Flag on Cookie: {cookie_name}",
                    "category": "Cryptographic & Session Failures",
                    "severity": "Medium",
                    "evidence": f"Cookie '{cookie_name}' lacks HttpOnly directive.",
                    "description": "JavaScript can read this cookie, increasing risk of credential exposure via XSS.",
                    "impact": "Session token compromise if a script injection vulnerability exists.",
                    "recommendation": "Set the 'HttpOnly' flag during Set-Cookie initialization.",
                    "status": "Open"
                })

            if not is_secure and target_url.startswith("https://"):
                findings.append({
                    "id": f"CK-SECURE-{cookie_name}",
                    "title": f"Missing Secure Flag on Cookie: {cookie_name}",
                    "category": "Cryptographic & Session Failures",
                    "severity": "Medium",
                    "evidence": f"Cookie '{cookie_name}' transmitted over HTTPS without Secure flag.",
                    "description": "Cookie can be transmitted over unencrypted HTTP connections.",
                    "impact": "Interception via network eavesdropping on cleartext channels.",
                    "recommendation": "Configure Set-Cookie with the 'Secure' attribute.",
                    "status": "Open"
                })

        return findings
