import socket
from urllib.parse import urlparse

class PortScanner:
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 3000: "Node/React Dev",
        3306: "MySQL", 5432: "PostgreSQL", 8000: "Dev Web",
        8080: "HTTP-Proxy/Alt"
    }

    @classmethod
    def scan_host(cls, target_url_or_ip: str, ports: list[int] = None) -> list[dict]:
        ports = ports or list(cls.COMMON_PORTS.keys())
        parsed = urlparse(target_url_or_ip if "://" in target_url_or_ip else f"http://{target_url_or_ip}")
        host = parsed.hostname or target_url_or_ip.split(":")[0]

        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = cls.COMMON_PORTS.get(port, "Unknown")
                    finding = {
                        "id": f"PORT-{port}",
                        "port": port,
                        "service": service,
                        "state": "open",
                        "severity": "Medium" if port in {21, 3306, 5432} else "Informational",
                        "title": f"Open Port Detected: {port} ({service})",
                        "category": "Network Exposure",
                        "evidence": f"Port {port}/TCP accepted handshake on {host}",
                        "description": f"Port {port} hosting {service} is exposed and accepting TCP connections.",
                        "impact": "Exposed service attack surface if unauthenticated or misconfigured.",
                        "recommendation": "Close unused ports and apply strict local firewall rules.",
                        "status": "Open"
                    }
                    open_ports.append(finding)
        return open_ports
