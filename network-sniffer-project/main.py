"""
main.py
=======
Command-line user interface and orchestrator for the Basic Network Sniffer.
Provides an interactive menu for interface discovery, real-time packet capture,
protocol filtering, traffic statistics, and Pandas-powered CSV exports.
"""

import sys
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
import pandas as pd

# Ensure local modules can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packet_analyzer import (
    analyze_packet,
    calculate_packet_statistics,
    parse_tcp_flags,
    extract_dns_query,
)
from packet_capture import PacketCaptureEngine


class NetworkSnifferCLI:
    """Terminal-based user interface and coordinator for packet sniffing operations."""

    def __init__(self):
        self.engine = PacketCaptureEngine()
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        os.makedirs(self.output_dir, exist_ok=True)
        self.selected_interface_obj: Any = None
        self.selected_interface_name: str = "Default (Auto)"

    def clear_screen(self) -> None:
        """Clear the terminal screen cleanly across Windows and Unix."""
        os.system("cls" if os.name == "nt" else "clear")

    def display_banner(self) -> None:
        """Render the application header and live status bar."""
        print("=" * 55)
        print("            BASIC NETWORK SNIFFER")
        print("        Network Traffic Analysis Tool")
        print("=" * 55)

        # Live status indicators
        if self.engine.is_running:
            status_text = f"[ACTIVE - CAPTURING]  Packets: {self.engine.get_packet_count()}"
            iface_text = f"Interface: {self.engine.active_interface}"
            print(f" Status: {status_text} | {iface_text}")
        else:
            err = self.engine.last_error
            count = self.engine.get_packet_count()
            if err:
                print(f" Status: [IDLE - LAST RUN REPORTED AN ISSUE] | Stored Packets: {count}")
            else:
                print(f" Status: [IDLE] | Stored Packets: {count} | Interface: {self.selected_interface_name}")
        print("-" * 55)

    def display_menu(self) -> None:
        """Print the primary 9-option interactive menu."""
        print("1. List available network interfaces")
        print("2. Start packet capture")
        print("3. Stop packet capture")
        print("4. View captured packet summaries")
        print("5. Filter packets by protocol")
        print("6. View packet statistics")
        print("7. Export packet metadata to CSV")
        print("8. Clear displayed packet history")
        print("9. Exit")
        print("=" * 55)

    def option_list_interfaces(self) -> None:
        """Menu Option 1: Discover and display network interfaces."""
        print("\n--- Available Network Interfaces ---")
        interfaces = self.engine.get_network_interfaces()

        if not interfaces:
            print("No network interfaces detected.")
            return

        print(f"{'#':<4} {'Name':<28} {'IP Address':<18} {'Description'}")
        print("-" * 80)
        for iface in interfaces:
            idx = iface["index"]
            name = iface["name"][:26]
            ip = iface["ip"] or "No IPv4"
            desc = iface["description"][:32]
            print(f"{idx:<4} {name:<28} {ip:<18} {desc}")

        print("\nTip: Choose an interface when starting capture, or use default auto-detection.")

    def option_start_capture(self) -> None:
        """Menu Option 2: Configure interface/filter and initiate capture."""
        if self.engine.is_running:
            print("\n[!] Packet capture is already running in the background.")
            print(f"    Current Packet Count: {self.engine.get_packet_count()}")
            return

        print("\n--- Start Packet Capture ---")
        interfaces = self.engine.get_network_interfaces()

        # Prompt user for interface selection
        print("Available interfaces:")
        for iface in interfaces:
            ip_str = f"({iface['ip']})" if iface['ip'] else ""
            print(f"  [{iface['index']}] {iface['name']} {ip_str} - {iface['description']}")
        print("  [0] Default (All / Scapy Auto-Detection)")

        choice = input("\nEnter interface number [0 for default]: ").strip()
        selected_dev = None
        selected_label = "Default (Auto)"

        if choice and choice != "0":
            try:
                c_idx = int(choice)
                match = next((item for item in interfaces if item["index"] == c_idx), None)
                if match:
                    selected_dev = match["scapy_dev"]
                    selected_label = match["name"]
                else:
                    print("[!] Invalid index selected. Using default auto-detection.")
            except ValueError:
                print("[!] Invalid input. Using default auto-detection.")

        self.selected_interface_obj = selected_dev
        self.selected_interface_name = selected_label

        # Optional BPF Filter prompt
        print("\nOptional BPF Filter (e.g. 'tcp', 'udp', 'icmp', 'port 53', 'ip host 192.168.1.1'):")
        bpf = input("Enter filter (leave blank for all traffic): ").strip()
        bpf_filter = bpf if bpf else None

        # Start capture
        success = self.engine.start_capture(
            scapy_interface=self.selected_interface_obj,
            bpf_filter=bpf_filter
        )

        if success:
            print(f"\n[+] Packet capture started successfully on: {self.selected_interface_name}")
            print(f"    Filter: {bpf_filter or 'All supported traffic'}")
            print("    The capture runs in a background thread while you use the menu.")
            # Give a brief moment for initial thread check
            time.sleep(0.5)
            if not self.engine.is_running and self.engine.last_error:
                print("\n[X] Capture stopped immediately due to an environment restriction:")
                print(self.engine.last_error)
        else:
            print(f"\n[X] Failed to start capture: {self.engine.last_error}")

    def option_stop_capture(self) -> None:
        """Menu Option 3: Cleanly terminate active packet capture."""
        if not self.engine.is_running:
            print("\n[!] Packet capture is not currently active.")
            if self.engine.last_error:
                print("\nLast error reported:")
                print(self.engine.last_error)
            return

        print("\nStopping packet capture worker cleanly...")
        self.engine.stop_capture()
        print(f"[+] Capture stopped. Total packets collected: {self.engine.get_packet_count()}")

    def option_view_summaries(self, packets_to_show: Optional[List[Dict[str, Any]]] = None) -> None:
        """Menu Option 4: View formatted packet summaries."""
        packets = packets_to_show if packets_to_show is not None else self.engine.get_packets()

        if not packets:
            print("\n[!] No packets in memory to display.")
            print("    Start a capture (Option 2) or generate sample test packets.")
            return

        print(f"\n--- Captured Packets (Total: {len(packets)}) ---")
        print(f"{'#':<5} {'Timestamp':<23} {'Proto':<7} {'Source IP:Port':<25} {'Dest IP:Port':<25} {'Len':<6} {'Details'}")
        print("-" * 115)

        # Pagination/Limit handling to keep terminal responsive
        limit = 25
        display_list = packets[-limit:] if len(packets) > limit else packets

        for pkt in display_list:
            num = pkt["packet_number"]
            ts = pkt["timestamp"]
            proto = pkt["protocol"]

            src = pkt["source_ip"]
            if pkt["source_port"] != "N/A":
                src = f"{src}:{pkt['source_port']}"

            dst = pkt["destination_ip"]
            if pkt["destination_port"] != "N/A":
                dst = f"{dst}:{pkt['destination_port']}"

            length = f"{pkt['length_bytes']}B"

            # Details
            details = []
            if pkt["tcp_flags"] != "N/A":
                details.append(f"Flags=[{pkt['tcp_flags']}]")
            if pkt["dns_query"] != "N/A":
                details.append(f'Query="{pkt["dns_query"]}"')
            detail_str = " ".join(details) if details else "-"

            print(f"{num:<5} {ts:<23} {proto:<7} {src[:24]:<25} {dst[:24]:<25} {length:<6} {detail_str[:28]}")

        if len(packets) > limit:
            print(f"\n* Showing most recent {limit} of {len(packets)} total packets.")
            print("  (Export to CSV via Option 7 to inspect all captured packets in detail).")

    def option_filter_packets(self) -> None:
        """Menu Option 5: Filter captured packet history by protocol."""
        packets = self.engine.get_packets()
        if not packets:
            print("\n[!] No packets in buffer to filter.")
            return

        print("\n--- Filter Packets by Protocol ---")
        print("Common options: TCP, UDP, ICMP, DNS, ARP, IPv6, OTHER, or ALL")
        choice = input("Enter protocol filter: ").strip().upper()

        if not choice or choice == "ALL":
            self.option_view_summaries(packets)
            return

        filtered = [
            p for p in packets
            if p.get("protocol", "").upper() == choice
            or (choice == "ICMP" and p.get("protocol", "").upper() in ("ICMP", "ICMPV6"))
        ]

        print(f"\nFiltered by '{choice}': Found {len(filtered)} matching packet(s).")
        if filtered:
            self.option_view_summaries(filtered)

    def option_view_statistics(self) -> None:
        """Menu Option 6: Compute and display aggregate traffic metrics."""
        packets = self.engine.get_packets()
        stats = calculate_packet_statistics(packets)

        total = stats["total_packets"]
        print("\n========================================")
        print("          PACKET STATISTICS")
        print("========================================")
        print(f" Total Captured Packets:       {total}")
        print(f" Total Captured Volume:        {stats['total_bytes']:,} bytes ({stats['total_bytes'] / 1024:.2f} KB)")
        print("-" * 40)
        print(" Protocol Breakdown:")

        def calc_pct(count: int, tot: int) -> str:
            return f"{count / tot * 100:.1f}%" if tot > 0 else "0.0%"

        print(f"   - TCP Packets:              {stats['tcp_count']:<6} ({calc_pct(stats['tcp_count'], total)})")
        print(f"   - UDP Packets:              {stats['udp_count']:<6} ({calc_pct(stats['udp_count'], total)})")
        print(f"   - ICMP Packets:             {stats['icmp_count']:<6} ({calc_pct(stats['icmp_count'], total)})")
        print(f"   - DNS Packets:              {stats['dns_count']:<6} ({calc_pct(stats['dns_count'], total)})")
        print(f"   - Other Protocols:          {stats['other_count']:<6} ({calc_pct(stats['other_count'], total)})")

        print("\n Top 5 Observed Source IP Addresses:")
        if stats["top_source_ips"]:
            for ip, cnt in stats["top_source_ips"]:
                print(f"   * {ip:<20} {cnt} packet(s) ({calc_pct(cnt, total)})")
        else:
            print("   (No valid IP sources observed)")

        print("\n Top 5 Observed Destination IP Addresses:")
        if stats["top_dest_ips"]:
            for ip, cnt in stats["top_dest_ips"]:
                print(f"   * {ip:<20} {cnt} packet(s) ({calc_pct(cnt, total)})")
        else:
            print("   (No valid IP destinations observed)")

        print("-" * 40)
        print(" Notice: These statistics describe strictly the packets")
        print("         this application has captured in this session.")
        print("========================================")

    def option_export_csv(self) -> None:
        """Menu Option 7: Export captured packet metadata to a timestamped CSV using Pandas."""
        packets = self.engine.get_packets()
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{timestamp_str}.csv"
        filepath = os.path.join(self.output_dir, filename)

        columns = [
            "packet_number",
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "length_bytes",
            "tcp_flags",
            "dns_query",
            "summary",
        ]

        column_headers = {
            "packet_number": "Packet_Number",
            "timestamp": "Timestamp",
            "source_ip": "Source_IP",
            "destination_ip": "Destination_IP",
            "protocol": "Protocol",
            "source_port": "Source_Port",
            "destination_port": "Destination_Port",
            "length_bytes": "Length_Bytes",
            "tcp_flags": "TCP_Flags",
            "dns_query": "DNS_Query",
            "summary": "Summary",
        }

        print("\n--- Exporting to CSV ---")

        if not packets:
            # Create an empty DataFrame with headers
            df = pd.DataFrame(columns=[column_headers[col] for col in columns])
            df.to_csv(filepath, index=False)
            print("[!] Warning: No packets have been captured yet.")
            print(f"[+] Created empty CSV file with standard headers at:\n    {filepath}")
            return

        # Convert to Pandas DataFrame
        df = pd.DataFrame(packets)[columns]
        df.rename(columns=column_headers, inplace=True)
        df.to_csv(filepath, index=False)

        print(f"[+] Successfully exported {len(packets)} packet record(s) to CSV!")
        print(f"    File path: {filepath}")
        print("    Columns exported: Packet_Number, Timestamp, Source_IP, Destination_IP,")
        print("                      Protocol, Source_Port, Destination_Port, Length_Bytes,")
        print("                      TCP_Flags, DNS_Query, Summary.")
        print("    (Note: Raw packet payloads are never exported for privacy and safety.)")

    def option_clear_history(self) -> None:
        """Menu Option 8: Clear stored packet history from memory."""
        count = self.engine.get_packet_count()
        if count == 0:
            print("\n[!] Packet history is already empty.")
            return

        confirm = input(f"\nAre you sure you want to clear all {count} captured packet records? (y/N): ").strip().lower()
        if confirm == "y":
            self.engine.clear_packets()
            print("[+] Packet history cleared successfully.")
        else:
            print("[-] Operation canceled.")

    def option_exit(self) -> None:
        """Menu Option 9: Gracefully stop background capture and exit."""
        if self.engine.is_running:
            print("\nStopping active packet capture thread before exit...")
            self.engine.stop_capture()
        print("\nThank you for using Basic Network Sniffer. Exiting cleanly.")
        sys.exit(0)

    def load_demo_packets(self) -> None:
        """
        Synthesize sample packets in memory for safe offline demonstration
        when live raw sockets or Npcap are unavailable.
        """
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP

        demo_packets = [
            IP(src="192.168.1.105", dst="142.250.190.46") / TCP(sport=51234, dport=443, flags="S"),
            IP(src="142.250.190.46", dst="192.168.1.105") / TCP(sport=443, dport=51234, flags="SA"),
            IP(src="192.168.1.105", dst="142.250.190.46") / TCP(sport=51234, dport=443, flags="A"),
            IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(qd=DNSQR(qname="google.com")),
            IP(src="8.8.8.8", dst="192.168.1.105") / UDP(sport=53, dport=54321) / DNS(qd=DNSQR(qname="google.com")),
            IP(src="192.168.1.105", dst="1.1.1.1") / ICMP(),
            IP(src="1.1.1.1", dst="192.168.1.105") / ICMP(type=0),
            IPv6(src="2001:4860:4860::8888", dst="2401:4900::1") / UDP(sport=53, dport=61234),
            ARP(psrc="192.168.1.1", pdst="192.168.1.105"),
        ]

        for pkt in demo_packets:
            parsed = analyze_packet(pkt)
            self.engine.add_synthetic_packet(parsed)

        print(f"\n[+] Loaded {len(demo_packets)} synthetic demonstration packets into history!")

    def run(self) -> None:
        """Main application interactive loop."""
        while True:
            try:
                self.display_banner()
                self.display_menu()

                choice = input("Enter your choice (1-9): ").strip()

                if choice == "1":
                    self.option_list_interfaces()
                elif choice == "2":
                    self.option_start_capture()
                elif choice == "3":
                    self.option_stop_capture()
                elif choice == "4":
                    self.option_view_summaries()
                elif choice == "5":
                    self.option_filter_packets()
                elif choice == "6":
                    self.option_view_statistics()
                elif choice == "7":
                    self.option_export_csv()
                elif choice == "8":
                    self.option_clear_history()
                elif choice == "9":
                    self.option_exit()
                elif choice.lower() == "demo":
                    self.load_demo_packets()
                else:
                    print("\n[!] Invalid choice. Please enter a number between 1 and 9.")

                # Prompt user before refreshing menu
                print()
                input("Press [Enter] to continue...")
                self.clear_screen()

            except (KeyboardInterrupt, EOFError):
                print("\n[!] Interrupted by user.")
                self.option_exit()
            except Exception as e:
                print(f"\n[X] Application error: {e}")
                input("Press [Enter] to continue...")


if __name__ == "__main__":
    cli = NetworkSnifferCLI()
    cli.run()
