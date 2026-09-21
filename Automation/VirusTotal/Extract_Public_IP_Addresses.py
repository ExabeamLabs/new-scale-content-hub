# Author: Exabeam Labs
# Version: 1.2
# Date updated: Sept 21 2026
# Action Name: Extract_Public_IP_Addresses
# Description: Extract and return only public ip addresses.

import ipaddress


def main(src_ips: list, dest_ips: list) -> list:
    """
    Extract external public IPv4 addresses from source and destination IP lists.

    Args:
        src_ips:  List of source IP addresses
        dest_ips: List of destination IP addresses

    Returns:
        list: Valid public IPv4 addresses only
    """
    public_ips = set()
    for ip in (src_ips or []) + (dest_ips or []):
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            continue

        if address.version == 4 and address.is_global:
            public_ips.add(str(address))

    return sorted(public_ips)