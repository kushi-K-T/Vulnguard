import ipaddress
import socket
from urllib.parse import urlparse

class TargetValidator:
    """Restricts scanning exclusively to localhost and RFC 1918 private networks."""
    
    @staticmethod
    def is_safe_target(target_input: str) -> tuple[bool, str]:
        if not target_input:
            return False, "Target cannot be empty."

        parsed = urlparse(target_input if "://" in target_input else f"http://{target_input}")
        hostname = parsed.hostname or target_input.split(":")[0]

        if not hostname:
            return False, "Invalid target format."

        if hostname.lower() in {"localhost", "127.0.0.1", "::1"} or hostname.lower().endswith(".local"):
            return True, "Authorized Localhost/Lab Domain."

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True, f"Authorized Private IP Range: {ip}"
            return False, f"Prohibited Target: {ip} is a public Internet address."
        except ValueError:
            pass

        try:
            resolved_ip_str = socket.gethostbyname(hostname)
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            if resolved_ip.is_private or resolved_ip.is_loopback:
                return True, f"Resolved to Private IP: {resolved_ip}"
            return False, f"Target resolved to public IP ({resolved_ip_str}). Scanning denied."
        except socket.error:
            return False, f"Could not resolve host: {hostname}"
