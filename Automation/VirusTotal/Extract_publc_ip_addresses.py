"""
Extract and return only external (public) IP addresses from a given list
Description: Extracts and returns only external (public) IP addresses from a given list,
             filtering out private, loopback, link-local and reserved ranges
             (RFC 1918, RFC 5735). Invalid IPv4 addresses are silently ignored.
"""

import re

# IPv4 validation pattern — matches x.x.x.x where each octet is 0-255
_IPV4_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$"
)


def is_valid_ipv4(ip: str) -> bool:
    """Return True if the given string is a valid IPv4 address."""
    return bool(_IPV4_PATTERN.match(str(ip).strip()))


def match(range_from: str, range_to: str, ip: str) -> bool:
    """Return True if ip falls within the given IPv4 range (inclusive)."""
    min_ip = [int(o) for o in range_from.split(".")]
    max_ip = [int(o) for o in range_to.split(".")]
    octets = [int(o) for o in ip.split(".")]
    return all(min_ip[i] <= octets[i] <= max_ip[i] for i in range(4))


def main(src_ips: list, dest_ips: list) -> list:
    """
    Extract external public IPv4 addresses from source and destination IP lists.

    Args:
        src_ips:  List of source IP addresses
        dest_ips: List of destination IP addresses

    Returns:
        list: Valid public IPv4 addresses only
    """
    combined = set(src_ips) | set(dest_ips)

    # Filter out invalid IPv4 entries silently
    valid = {ip for ip in combined if is_valid_ipv4(ip)}

    # Filter out private, loopback and reserved ranges
    return [
        ip for ip in valid
        if not (
            match("10.0.0.0",    "10.255.255.255", ip) or
            match("172.16.0.0",  "172.31.255.255",  ip) or
            match("192.168.0.0", "192.168.255.255", ip) or
            ip == "127.0.0.1"
        )
    ]
