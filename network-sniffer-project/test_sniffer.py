"""
test_sniffer.py
===============
Automated test suite for Network Sniffer Project.
Uses synthetic packets constructed in-memory with Scapy.
Requires NO live network access, NO root/administrator privileges, and NO Npcap.
Verifies analyzer logic, header extraction, filtering, statistics, and CSV export.
"""

import os
import sys
import tempfile
import unittest
import pandas as pd

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Ether, Raw
from packet_analyzer import (
    analyze_packet,
    calculate_packet_statistics,
    parse_tcp_flags,
    extract_dns_query,
)


class TestPacketAnalyzer(unittest.TestCase):
    """Test suite for packet analysis and metadata parsing."""

    def test_ipv4_tcp_parsing(self):
        """Test IPv4 TCP packet parsing including port numbers and TCP flags."""
        packet = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=54321, dport=443, flags="SA")
        parsed = analyze_packet(packet, packet_number=1)

        self.assertEqual(parsed["packet_number"], 1)
        self.assertEqual(parsed["source_ip"], "192.168.1.50")
        self.assertEqual(parsed["destination_ip"], "93.184.216.34")
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["source_port"], 54321)
        self.assertEqual(parsed["destination_port"], 443)
        self.assertIn("SYN", parsed["tcp_flags"])
        self.assertIn("ACK", parsed["tcp_flags"])
        self.assertGreater(parsed["length_bytes"], 0)
        self.assertIn("[TCP]", parsed["summary"])
        self.assertIn("192.168.1.50:54321 -> 93.184.216.34:443", parsed["summary"])

    def test_ipv6_udp_parsing(self):
        """Test IPv6 UDP packet parsing where supported."""
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=60000, dport=8080)
        parsed = analyze_packet(packet, packet_number=2)

        self.assertEqual(parsed["packet_number"], 2)
        self.assertEqual(parsed["source_ip"], "2001:db8::1")
        self.assertEqual(parsed["destination_ip"], "2001:db8::2")
        self.assertEqual(parsed["protocol"], "UDP")
        self.assertEqual(parsed["source_port"], 60000)
        self.assertEqual(parsed["destination_port"], 8080)
        self.assertEqual(parsed["tcp_flags"], "N/A")
        self.assertGreater(parsed["length_bytes"], 0)

    def test_icmp_parsing(self):
        """Test ICMP echo packet parsing and missing port handling."""
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        parsed = analyze_packet(packet, packet_number=3)

        self.assertEqual(parsed["source_ip"], "10.0.0.1")
        self.assertEqual(parsed["destination_ip"], "10.0.0.2")
        self.assertEqual(parsed["protocol"], "ICMP")
        self.assertEqual(parsed["source_port"], "N/A")
        self.assertEqual(parsed["destination_port"], "N/A")
        self.assertEqual(parsed["tcp_flags"], "N/A")

    def test_dns_query_parsing(self):
        """Test DNS over UDP packet parsing and query name extraction."""
        packet = (
            IP(src="192.168.1.20", dst="8.8.8.8")
            / UDP(sport=53535, dport=53)
            / DNS(qd=DNSQR(qname="cybersecurity.test.org"))
        )
        parsed = analyze_packet(packet, packet_number=4)

        self.assertEqual(parsed["protocol"], "DNS")
        self.assertEqual(parsed["source_port"], 53535)
        self.assertEqual(parsed["destination_port"], 53)
        self.assertEqual(parsed["dns_query"], "cybersecurity.test.org")
        self.assertIn('Query="cybersecurity.test.org"', parsed["summary"])

    def test_missing_ip_and_ports_arp(self):
        """Test non-IP frame parsing (e.g. ARP) for safe handling of missing fields."""
        packet = ARP(psrc="192.168.1.1", pdst="192.168.1.254")
        parsed = analyze_packet(packet, packet_number=5)

        self.assertEqual(parsed["protocol"], "ARP")
        self.assertEqual(parsed["source_ip"], "192.168.1.1")
        self.assertEqual(parsed["destination_ip"], "192.168.1.254")
        self.assertEqual(parsed["source_port"], "N/A")
        self.assertEqual(parsed["destination_port"], "N/A")
        self.assertEqual(parsed["tcp_flags"], "N/A")
        self.assertEqual(parsed["dns_query"], "N/A")

    def test_non_ip_raw_frame(self):
        """Test raw non-IP frame without crash."""
        packet = Ether() / Raw(load=b"TESTPAYLOAD")
        parsed = analyze_packet(packet, packet_number=6)

        self.assertEqual(parsed["source_ip"], "N/A")
        self.assertEqual(parsed["destination_ip"], "N/A")
        self.assertEqual(parsed["source_port"], "N/A")
        self.assertEqual(parsed["destination_port"], "N/A")
        self.assertIn("Non-IP Frame", parsed["summary"])

    def test_empty_capture_statistics(self):
        """Test statistics calculation when zero packets have been captured."""
        stats = calculate_packet_statistics([])
        self.assertEqual(stats["total_packets"], 0)
        self.assertEqual(stats["tcp_count"], 0)
        self.assertEqual(stats["udp_count"], 0)
        self.assertEqual(stats["icmp_count"], 0)
        self.assertEqual(stats["dns_count"], 0)
        self.assertEqual(stats["other_count"], 0)
        self.assertEqual(stats["total_bytes"], 0)
        self.assertEqual(stats["top_source_ips"], [])
        self.assertEqual(stats["top_dest_ips"], [])

    def test_statistics_aggregation(self):
        """Test aggregate statistics computation over multiple packets."""
        packets = [
            {"protocol": "TCP", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "length_bytes": 100},
            {"protocol": "TCP", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "length_bytes": 200},
            {"protocol": "UDP", "source_ip": "10.0.0.3", "destination_ip": "10.0.0.2", "length_bytes": 150},
            {"protocol": "DNS", "source_ip": "10.0.0.1", "destination_ip": "8.8.8.8", "length_bytes": 80},
            {"protocol": "ICMP", "source_ip": "10.0.0.4", "destination_ip": "10.0.0.1", "length_bytes": 64},
            {"protocol": "OTHER", "source_ip": "N/A", "destination_ip": "N/A", "length_bytes": 50},
        ]
        stats = calculate_packet_statistics(packets)

        self.assertEqual(stats["total_packets"], 6)
        self.assertEqual(stats["tcp_count"], 2)
        self.assertEqual(stats["udp_count"], 1)
        self.assertEqual(stats["dns_count"], 1)
        self.assertEqual(stats["icmp_count"], 1)
        self.assertEqual(stats["other_count"], 1)
        self.assertEqual(stats["total_bytes"], 644)
        # Most frequent source IP should be 10.0.0.1 (3 packets)
        self.assertEqual(stats["top_source_ips"][0][0], "10.0.0.1")
        self.assertEqual(stats["top_source_ips"][0][1], 3)

    def test_protocol_filtering(self):
        """Test filtering parsed packets by protocol name."""
        packets = [
            {"packet_number": 1, "protocol": "TCP"},
            {"packet_number": 2, "protocol": "UDP"},
            {"packet_number": 3, "protocol": "TCP"},
            {"packet_number": 4, "protocol": "DNS"},
            {"packet_number": 5, "protocol": "ICMP"},
        ]
        tcp_only = [p for p in packets if p["protocol"] == "TCP"]
        dns_only = [p for p in packets if p["protocol"] == "DNS"]

        self.assertEqual(len(tcp_only), 2)
        self.assertEqual([p["packet_number"] for p in tcp_only], [1, 3])
        self.assertEqual(len(dns_only), 1)
        self.assertEqual(dns_only[0]["packet_number"], 4)

    def test_pandas_csv_export(self):
        """Test exporting packet data to CSV using Pandas and verify content."""
        packets = [
            {
                "packet_number": 1,
                "timestamp": "2026-10-26 18:00:00.000",
                "source_ip": "192.168.1.10",
                "destination_ip": "93.184.216.34",
                "protocol": "TCP",
                "source_port": 50000,
                "destination_port": 443,
                "length_bytes": 60,
                "tcp_flags": "SYN",
                "dns_query": "N/A",
                "summary": "[TCP] 192.168.1.10:50000 -> 93.184.216.34:443 Flags=[SYN] Len=60B",
            }
        ]

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            df = pd.DataFrame(packets)
            df.to_csv(tmp_path, index=False)

            self.assertTrue(os.path.exists(tmp_path))
            read_df = pd.read_csv(tmp_path)
            self.assertEqual(len(read_df), 1)
            self.assertEqual(read_df.loc[0, "protocol"], "TCP")
            self.assertEqual(read_df.loc[0, "source_ip"], "192.168.1.10")
            self.assertEqual(read_df.loc[0, "tcp_flags"], "SYN")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_empty_pandas_csv_export(self):
        """Test exporting an empty dataset to CSV with valid column headers."""
        columns = [
            "Packet_Number", "Timestamp", "Source_IP", "Destination_IP",
            "Protocol", "Source_Port", "Destination_Port", "Length_Bytes",
            "TCP_Flags", "DNS_Query", "Summary"
        ]
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            df = pd.DataFrame(columns=columns)
            df.to_csv(tmp_path, index=False)

            self.assertTrue(os.path.exists(tmp_path))
            read_df = pd.read_csv(tmp_path)
            self.assertEqual(len(read_df), 0)
            self.assertListEqual(list(read_df.columns), columns)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
