import socket
import ssl
from urllib.parse import urlparse

class TLSScanner:
    @staticmethod
    def scan(target_url: str) -> list[dict]:
        findings = []
        parsed = urlparse(target_url)
        
        if parsed.scheme != "https":
            return [{
                "id": "TLS-NO-HTTPS",
                "title": "Cleartext HTTP Protocol in Use",
                "category": "Cryptographic Failures",
                "severity": "High",
                "evidence": f"Target endpoint is served via {target_url}",
                "description": "Data transferred over cleartext HTTP is susceptible to inspection and tampering.",
                "impact": "Exposure of credentials, parameters, and sensitive application payloads.",
                "recommendation": "Configure a TLS certificate and enforce HTTPS redirects.",
                "status": "Open"
            }]

        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()

        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_version = ssock.version()
                    if tls_version in {"TLSv1", "TLSv1.1"}:
                        findings.append({
                            "id": "TLS-DEPRECATED",
                            "title": f"Deprecated TLS Protocol Version ({tls_version})",
                            "category": "Cryptographic Failures",
                            "severity": "High",
                            "evidence": f"Negotiated Protocol: {tls_version}",
                            "description": "The server permits legacy TLS protocols with known cipher weaknesses.",
                            "impact": "Susceptibility to cryptographic downgrade attacks.",
                            "recommendation": "Disable TLS 1.0 and 1.1; enforce TLS 1.2 or TLS 1.3.",
                            "status": "Open"
                        })
        except ssl.SSLError as e:
            findings.append({
                "id": "TLS-CERT-ERR",
                "title": "TLS Certificate Validation Failure",
                "category": "Cryptographic Failures",
                "severity": "Medium",
                "evidence": f"SSL Handshake failed: {str(e)}",
                "description": "Target presented an untrusted, self-signed, or expired SSL certificate.",
                "impact": "Browser trust warnings and vulnerability to adversary-in-the-middle attacks.",
                "recommendation": "Deploy a valid certificate issued by a trusted Certificate Authority.",
                "status": "Open"
            })
        except Exception:
            pass

        return findings
