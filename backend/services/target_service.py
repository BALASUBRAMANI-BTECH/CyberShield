import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional


# Disallowed dangerous ranges / SSRF targets
BLOCKED_METADATA_IPS = [
    ipaddress.ip_network("169.254.169.254/32"),  # Cloud metadata (AWS, Azure, GCP, OpenStack)
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local RFC 3927
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
]

# Standard approved lab ranges
DEFAULT_LAB_ALLOWLIST = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
]


class TargetSecurityService:
    @staticmethod
    def extract_host(target_str: str) -> str:
        """Extract clean hostname or IP from URL or raw target input."""
        cleaned = target_str.strip()
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            hostname = parsed.hostname or cleaned
            return hostname
        # If contains port without schema (e.g. localhost:3000)
        if ":" in cleaned and not cleaned.startswith("[") and "/" not in cleaned:
            parts = cleaned.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0]
        return cleaned

    @classmethod
    def validate_target(cls, target_str: str, allow_public: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Validates target against SSRF attacks and checks lab allowlist.
        Returns: (is_valid, message, normalized_host)
        """
        if not target_str or len(target_str.strip()) < 1:
            return False, "Target address cannot be empty.", None

        host = cls.extract_host(target_str)

        # Basic format check
        if not re.match(r"^[a-zA-Z0-9.\-_:\[\]]+$", host):
            return False, f"Target contains invalid or forbidden characters: '{host}'", None

        # Resolve to IP if hostname
        try:
            # Check if direct IP
            try:
                ip_obj = ipaddress.ip_address(host)
            except ValueError:
                # Handle 'localhost' explicitly
                if host.lower() == "localhost":
                    ip_obj = ipaddress.ip_address("127.0.0.1")
                else:
                    # DNS resolution with safe timeout
                    resolved = socket.gethostbyname(host)
                    ip_obj = ipaddress.ip_address(resolved)
        except Exception as e:
            # If DNS fails for a purely synthetic lab hostname, allow if ending in .local/.lab/.internal
            if host.endswith((".lab", ".local", ".internal", ".test")):
                return True, "Authorized isolated lab domain registered.", host
            return False, f"Could not resolve target address '{host}': {str(e)}", None

        # 1. SSRF Check: Is it a cloud metadata address?
        for blocked_net in BLOCKED_METADATA_IPS:
            if ip_obj in blocked_net:
                return False, f"Security Violation: Target IP '{ip_obj}' is a blocked link-local/cloud metadata address (SSRF Protection).", None

        # 2. Allowlist Check: Is it in approved local lab ranges?
        is_lab_authorized = False
        for allowed_net in DEFAULT_LAB_ALLOWLIST:
            if ip_obj in allowed_net:
                is_lab_authorized = True
                break

        if not is_lab_authorized and not allow_public:
            return False, (
                f"Scope Restriction: Target '{ip_obj}' is outside authorized private lab subnets "
                f"(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). "
                f"Active testing against non-lab public systems is strictly prevented."
            ), None

        return True, "Target verified and authorized within lab scope.", host
