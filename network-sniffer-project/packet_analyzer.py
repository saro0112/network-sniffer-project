"""
packet_analyzer.py
==================
Module for inspecting, parsing, and analyzing network packet headers.
Extracts metadata from captured Scapy packets into clean, structured dictionaries.
Strictly focuses on packet headers and metadata; never stores raw private payloads.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import Counter


# TCP flag bitmask mapping for human-readable representation
TCP_FLAGS_MAP = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def parse_tcp_flags(tcp_layer: Any) -> str:
    """
    Extract and format TCP control flags into a readable string (e.g., 'SYN, ACK').
    
    Args:
        tcp_layer: Scapy TCP layer object
        
    Returns:
        Comma-separated string of active TCP flags, or 'N/A' if unavailable.
    """
    if tcp_layer is None or not hasattr(tcp_layer, "flags"):
        return "N/A"

    flags_val = tcp_layer.flags
    active_flags = []

    # Handle Scapy FlagValue or integer bitmask
    try:
        flag_int = int(flags_val)
        for mask, name in TCP_FLAGS_MAP.items():
            if flag_int & mask:
                active_flags.append(name)
    except (ValueError, TypeError):
        # Fallback to string representation if conversion fails
        flag_str = str(flags_val)
        for char in flag_str:
            name = {
                "F": "FIN",
                "S": "SYN",
                "R": "RST",
                "P": "PSH",
                "A": "ACK",
                "U": "URG",
                "E": "ECE",
                "C": "CWR",
            }.get(char.upper())
            if name and name not in active_flags:
                active_flags.append(name)

    return ", ".join(active_flags) if active_flags else "NONE"


def extract_dns_query(dns_layer: Any) -> str:
    """
    Safely extract DNS query name from a DNS packet layer.
    
    Args:
        dns_layer: Scapy DNS layer object
        
    Returns:
        DNS queried domain name, or 'N/A' if none or error.
    """
    if dns_layer is None:
        return "N/A"

    try:
        # Check Question Record (qd)
        if hasattr(dns_layer, "qd") and dns_layer.qd is not None:
            qd = dns_layer.qd
            # Support both PacketListField and scalar layer
            record = qd[0] if (isinstance(qd, list) or hasattr(qd, "__getitem__")) and len(qd) > 0 else qd
            qname = getattr(record, "qname", None)
            if qname:
                if isinstance(qname, bytes):
                    decoded = qname.decode("utf-8", errors="replace")
                else:
                    decoded = str(qname)
                return decoded.rstrip(".")

        # Fallback: check Answer Record (an)
        if hasattr(dns_layer, "an") and dns_layer.an is not None:
            an = dns_layer.an
            record = an[0] if (isinstance(an, list) or hasattr(an, "__getitem__")) and len(an) > 0 else an
            rrname = getattr(record, "rrname", None)
            if rrname:
                if isinstance(rrname, bytes):
                    decoded = rrname.decode("utf-8", errors="replace")
                else:
                    decoded = str(rrname)
                return decoded.rstrip(".")
    except Exception:
        pass

    return "N/A"


def analyze_packet(packet: Any, packet_number: int = 1) -> Dict[str, Any]:
    """
    Parse a network packet and extract structured metadata.
    
    Identifies:
      - Network layer: IPv4, IPv6, ARP, or Non-IP
      - Transport layer: TCP, UDP, ICMP, DNS
      - Ports, Flags, DNS Queries, Packet Length, Timestamps
    
    Args:
        packet: Scapy packet object
        packet_number: Sequential index of the packet in the current session
        
    Returns:
        A dictionary containing structured, safe packet metadata.
    """
    # 1. Timestamp extraction
    pkt_time = getattr(packet, "time", None)
    if pkt_time:
        try:
            timestamp = datetime.fromtimestamp(float(pkt_time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except Exception:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # 2. Length in bytes
    length_bytes = len(packet) if packet is not None else 0

    # Initialize default metadata
    source_ip = "N/A"
    dest_ip = "N/A"
    protocol = "OTHER"
    source_port: Any = "N/A"
    dest_port: Any = "N/A"
    tcp_flags = "N/A"
    dns_query = "N/A"

    # Check for lazy layer imports inside function to guard against partial environments
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, ARP

    # 3. Layer 3 (Network Layer) Parsing
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        protocol = "IPv4"
    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        source_ip = ipv6_layer.src
        dest_ip = ipv6_layer.dst
        protocol = "IPv6"
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        source_ip = getattr(arp_layer, "psrc", "N/A")
        dest_ip = getattr(arp_layer, "pdst", "N/A")
        protocol = "ARP"

    # 4. Layer 4 & Application Layer (Transport & Protocol Identification)
    # Check DNS first (usually runs over UDP/TCP port 53)
    if packet.haslayer(DNS):
        protocol = "DNS"
        dns_query = extract_dns_query(packet[DNS])
        if packet.haslayer(UDP):
            source_port = int(packet[UDP].sport)
            dest_port = int(packet[UDP].dport)
        elif packet.haslayer(TCP):
            source_port = int(packet[TCP].sport)
            dest_port = int(packet[TCP].dport)
            tcp_flags = parse_tcp_flags(packet[TCP])

    elif packet.haslayer(TCP):
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        dest_port = int(packet[TCP].dport)
        tcp_flags = parse_tcp_flags(packet[TCP])

    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        dest_port = int(packet[UDP].dport)

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    elif packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply"):
        protocol = "ICMPv6"

    # 5. Build Safe One-Line Summary (No raw application payload content)
    summary_parts = [f"[{protocol}]"]
    if source_ip != "N/A":
        src_str = f"{source_ip}:{source_port}" if source_port != "N/A" else source_ip
        dst_str = f"{dest_ip}:{dest_port}" if dest_port != "N/A" else dest_ip
        summary_parts.append(f"{src_str} -> {dst_str}")
    else:
        summary_parts.append("Non-IP Frame")

    if tcp_flags != "N/A":
        summary_parts.append(f"Flags=[{tcp_flags}]")

    if dns_query != "N/A":
        summary_parts.append(f'Query="{dns_query}"')

    summary_parts.append(f"Len={length_bytes}B")
    safe_summary = " ".join(summary_parts)

    return {
        "packet_number": packet_number,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": dest_port,
        "length_bytes": length_bytes,
        "tcp_flags": tcp_flags,
        "dns_query": dns_query,
        "summary": safe_summary,
    }


def calculate_packet_statistics(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate summary statistics over a collection of analyzed packet dictionaries.
    
    Args:
        packets: List of packet metadata dictionaries
        
    Returns:
        Structured dictionary containing counts, top IP addresses, and byte totals.
    """
    total_packets = len(packets)
    if total_packets == 0:
        return {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "dns_count": 0,
            "other_count": 0,
            "total_bytes": 0,
            "top_source_ips": [],
            "top_dest_ips": [],
        }

    tcp_count = sum(1 for p in packets if p.get("protocol") == "TCP")
    udp_count = sum(1 for p in packets if p.get("protocol") == "UDP")
    icmp_count = sum(1 for p in packets if p.get("protocol") in ("ICMP", "ICMPv6"))
    dns_count = sum(1 for p in packets if p.get("protocol") == "DNS")
    other_count = total_packets - (tcp_count + udp_count + icmp_count + dns_count)

    total_bytes = sum(int(p.get("length_bytes", 0)) for p in packets)

    # Calculate top source and destination IPs (excluding 'N/A')
    src_ips = [p.get("source_ip") for p in packets if p.get("source_ip") and p.get("source_ip") != "N/A"]
    dst_ips = [p.get("destination_ip") for p in packets if p.get("destination_ip") and p.get("destination_ip") != "N/A"]

    top_sources = Counter(src_ips).most_common(5)
    top_destinations = Counter(dst_ips).most_common(5)

    return {
        "total_packets": total_packets,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "dns_count": dns_count,
        "other_count": other_count,
        "total_bytes": total_bytes,
        "top_source_ips": top_sources,
        "top_dest_ips": top_destinations,
    }
