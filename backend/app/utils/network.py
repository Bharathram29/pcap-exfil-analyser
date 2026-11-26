"""IP address classification and network utility helpers."""

from __future__ import annotations

import ipaddress

_INTERNAL_V4_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 CGNAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("0.0.0.0/8"),
)

_INTERNAL_V6_NETS = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # Unique local addresses
    ipaddress.ip_network("fe80::/10"),  # Link-local
)


def is_internal_ip(ip_str: str | None) -> bool:
    """Return True if the IP belongs to RFC 1918, CGNAT, loopback, link-local, or ULA ranges."""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if addr.is_multicast or addr.is_unspecified:
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _INTERNAL_V4_NETS)
    return any(addr in net for net in _INTERNAL_V6_NETS)


def is_external_ip(ip_str: str | None) -> bool:
    """Return True if the IP is a valid non-internal unicast address."""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not is_internal_ip(ip_str)


def classify_direction(src_ip: str | None, dst_ip: str | None) -> str:
    """Classify traffic direction from endpoint IP address spaces."""
    src_int = is_internal_ip(src_ip)
    dst_int = is_internal_ip(dst_ip)
    src_ext = is_external_ip(src_ip)
    dst_ext = is_external_ip(dst_ip)

    if src_int and dst_ext:
        return "outbound"
    if src_ext and dst_int:
        return "inbound"
    if src_int and dst_int:
        return "internal"
    if src_ext and dst_ext:
        return "external"
    return "unknown"
