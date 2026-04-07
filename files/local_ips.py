#!/usr/bin/env python3
"""Print local IP addresses by reading /proc/net directly."""

import ipaddress
import re

IPV6_SCOPE = {
    0x00: "global",
    0x10: "loopback",
    0x20: "link-local",
    0x40: "site-local",
    0x80: "compat",
}


def get_interfaces():
    """Return interface names in order from /proc/net/dev."""
    ifaces = []
    with open("/proc/net/dev") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                iface = line.split(":")[0].strip()
                ifaces.append(iface)
    return ifaces


def parse_ipv4():
    """Yield (iface, ip_str) pairs from /proc/net/fib_trie.

    The trie format pairs an IP line (|-- x.x.x.x) with a type line
    (/prefix host LOCAL). We only want /32 host LOCAL entries (actual host
    addresses). Network-scoped LOCAL entries (e.g. /8 host LOCAL for 127.0.0.0)
    are skipped.

    Interface is determined by matching each address against subnets in
    /proc/net/route. Loopback addresses (127.x.x.x) are not in that table
    and are mapped to "lo" directly.
    """
    # Step 1: collect /32 LOCAL IPv4 addresses from fib_trie
    local_ips = []
    prev_ip = None
    with open("/proc/net/fib_trie") as f:
        for line in f:
            stripped = line.strip()
            # IP candidate line: starts with |-- followed by dotted decimal
            m = re.match(r"\|--\s+(\d+\.\d+\.\d+\.\d+)$", stripped)
            if m:
                prev_ip = m.group(1)
            elif stripped.endswith("LOCAL") and prev_ip:
                # Only emit true host addresses (/32); skip network-scoped LOCAL
                if re.match(r"/32\s+host\s+LOCAL$", stripped):
                    ip = prev_ip
                    if ip not in ("0.0.0.0", "255.255.255.255"):
                        local_ips.append(ip)
                prev_ip = None
            else:
                if not stripped.startswith("|--"):
                    prev_ip = None

    # Step 2: map each local IP to an interface via /proc/net/route
    # /proc/net/route columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
    # Destination and Mask are hex little-endian 32-bit values
    routes = []
    with open("/proc/net/route") as f:
        next(f)  # skip header
        for line in f:
            parts = line.split()
            if len(parts) < 8:
                continue
            iface = parts[0]
            dest = int(parts[1], 16)
            mask = int(parts[7], 16)
            routes.append((iface, dest, mask))

    def ip_to_int(ip_str):
        parts = [int(x) for x in ip_str.split(".")]
        return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)

    results = []
    seen = set()
    for ip_str in local_ips:
        if ip_str in seen:
            continue
        seen.add(ip_str)
        # Loopback addresses are not in /proc/net/route; assign directly to lo
        if ip_str.startswith("127."):
            results.append(("lo", ip_str))
            continue
        ip_int = ip_to_int(ip_str)
        matched_iface = None
        best_prefix = -1
        for iface, dest, mask in routes:
            if mask == 0:
                continue
            if (ip_int & mask) == (dest & mask):
                prefix_len = bin(mask).count("1")
                if prefix_len > best_prefix:
                    best_prefix = prefix_len
                    matched_iface = iface
        results.append((matched_iface or "?", ip_str))

    return results


def parse_ipv6():
    """Yield (iface, address, scope_name) from /proc/net/if_inet6."""
    results = []
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                hex_addr = parts[0]
                scope_val = int(parts[3], 16)
                iface = parts[5]
                # Insert colons to form a valid IPv6 address string
                groups = [hex_addr[i:i+4] for i in range(0, 32, 4)]
                addr_str = str(ipaddress.ip_address(":".join(groups)))
                scope_name = IPV6_SCOPE.get(scope_val, f"scope-{scope_val:#x}")
                results.append((iface, addr_str, scope_name))
    except FileNotFoundError:
        pass  # IPv6 not available
    return results


def main():
    iface_order = get_interfaces()
    iface_rank = {iface: i for i, iface in enumerate(iface_order)}

    ipv4 = parse_ipv4()
    ipv6 = parse_ipv6()

    # Collect all entries: (iface, address_str, family, extra)
    entries = []
    for iface, addr in ipv4:
        entries.append((iface, addr, 4, ""))
    for iface, addr, scope in ipv6:
        extra = f" ({scope})" if scope != "global" else ""
        entries.append((iface, addr, 6, extra))

    # Sort by interface order, then family
    entries.sort(key=lambda e: (iface_rank.get(e[0], 999), e[2]))

    if not entries:
        print("No addresses found.")
        return

    col = max(len(e[0]) for e in entries) + 2
    for iface, addr, _family, extra in entries:
        print(f"{iface:<{col}}{addr}{extra}")


if __name__ == "__main__":
    main()
