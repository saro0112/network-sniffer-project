# Basic Network Sniffer – Network Traffic Capture & Analysis Tool

A lightweight, robust, educational Python-based cybersecurity tool designed to capture, parse, and analyze network packets in real-time. Built specifically for network traffic monitoring on Windows and cross-platform systems using **Scapy** for packet parsing and **Pandas** for structured CSV data export.

---

## 1. Project Objective

The primary objective of this project is to provide a beginner-friendly yet technically rigorous network packet sniffer that:
- Captures network packets from local or explicitly authorized network interfaces.
- Inspects Layer 2, Layer 3, and Layer 4 packet headers without compromising user privacy.
- Identifies protocols including **IPv4**, **IPv6**, **TCP**, **UDP**, **ICMP**, and **DNS**.
- Dissects protocol-specific metadata (e.g., TCP control flags, DNS domain queries, port numbers, packet byte length).
- Computes aggregate session statistics (volume, protocol distribution, top communicating hosts).
- Exports structured packet metadata to timestamped CSV files using **Pandas**.
- Runs directly inside a terminal environment without bulky web frameworks.

---

## 2. Architecture & File Structure

```text
network-sniffer-project/
│
├── main.py                 # Interactive terminal UI, menus, CLI routing & controller
├── packet_capture.py       # Threaded Scapy sniffer, interface discovery & lifecycle
├── packet_analyzer.py      # Header inspection, protocol dissection & metric calculations
├── test_sniffer.py         # Automated unit test suite using synthetic in-memory packets
├── requirements.txt        # Third-party dependencies (Scapy, Pandas)
├── README.md               # Complete architecture, setup & troubleshooting documentation
└── output/                 # Destination directory for timestamped CSV exports
    └── .gitkeep
```

### Module Responsibilities

| File | Core Responsibilities |
| :--- | :--- |
| `packet_analyzer.py` | Extracts metadata (Source/Dest IP, Ports, Protocol, Length, Timestamps, TCP flags `SYN/ACK/FIN/RST`, DNS query names). Formats safe single-line summaries and computes session metrics. |
| `packet_capture.py` | Enumerates network interfaces via Scapy `conf.ifaces`. Spawns a background worker thread (`threading.Thread`) running `sniff(store=False, timeout=1)` to capture traffic asynchronously without freezing the user interface. |
| `main.py` | Renders a clean 9-option interactive command-line interface, handles user inputs, protocol filtering, Pandas CSV export, and safe cleanup. |
| `test_sniffer.py` | Verifies header parsing, missing field handling, protocol filtering, statistics, and CSV generation using synthetic packets (no live capture or admin privileges required). |

---

## 3. Technology Stack

- **Python 3.8+** (Tested on Python 3.14 on Windows)
- **Scapy (`>=2.5.0`)**: Low-level packet manipulation, sniffing, and header decoding.
- **Pandas (`>=2.0.0`)**: Structured data representation and CSV serialization.
- **Python Standard Library**: `threading`, `time`, `datetime`, `collections.Counter`, `unittest`, `logging`, `os`, `sys`.

---

## 4. Setup & Execution Instructions (Windows)

### Step 1: Verify Python Installation
Open PowerShell in Antigravity or Windows Terminal and verify Python is installed:
```powershell
py --version
```
*(Should output `Python 3.x.x`)*

### Step 2: Create a Python Virtual Environment
Navigate to the project directory and create an isolated virtual environment:
```powershell
py -m venv .venv
```

### Step 3: Activate Virtual Environment
In PowerShell, run:
```powershell
.\.venv\Scripts\Activate.ps1
```

> **Security Note on PowerShell Script Execution**:
> If Windows PowerShell restricts script execution with `PSSecurityException` (`running scripts is disabled on this system`), **do not weaken system execution policy**. Instead, run Python commands directly using the environment's executable:
> ```powershell
> .\.venv\Scripts\python.exe -m pip install -r requirements.txt
> .\.venv\Scripts\python.exe main.py
> ```

### Step 4: Install Dependencies
```powershell
py -m pip install -r requirements.txt
```

### Step 5: Run the Network Sniffer
```powershell
py main.py
```

---

## 5. Windows Packet Capture Requirements (Npcap)

Windows does not have built-in raw Layer 2 socket support in standard user mode. Therefore:

1. **Download Npcap**: Download the free installer from the official site:
   [https://npcap.com/#download](https://npcap.com/#download)
2. **Crucial Installation Option**: During installation, ensure the box:
   `[✓] Install Npcap in WinPcap API-compatible Mode`
   is **checked**. This allows Scapy to bind to your network adapters at Layer 2.
3. **Elevated Privileges**: If Npcap is not installed in service mode, run your terminal as **Administrator** to grant raw socket access.

---

## 6. Terminal User Interface & Menu Options

When launched, the sniffer displays an interactive menu with a live status bar:

```text
=======================================================
            BASIC NETWORK SNIFFER
        Network Traffic Analysis Tool
=======================================================
 Status: [IDLE] | Stored Packets: 0 | Interface: Default (Auto)
-------------------------------------------------------
1. List available network interfaces
2. Start packet capture
3. Stop packet capture
4. View captured packet summaries
5. Filter packets by protocol
6. View packet statistics
7. Export packet metadata to CSV
8. Clear displayed packet history
9. Exit
=======================================================
Enter your choice (1-9):
```

### Key Workflow:
1. **Option 1**: Inspect available network adapters and their assigned IP addresses.
2. **Option 2**: Choose an interface number (e.g. Wi-Fi) and optionally specify a BPF filter (e.g., `tcp`, `udp`, `port 53`, `icmp`). Capture starts in the background.
3. **Option 3**: Stop capture when desired.
4. **Option 4**: Display captured packets in a clear table:
   ```text
   #     Timestamp               Proto   Source IP:Port            Dest IP:Port              Len    Details
   -------------------------------------------------------------------------------------------------------------------
   1     2026-10-26 19:04:23.415 TCP     192.168.1.105:51234       142.250.190.46:443        40B    Flags=[SYN]
   2     2026-10-26 19:04:23.415 TCP     142.250.190.46:443        192.168.1.105:51234       40B    Flags=[SYN, ACK]
   3     2026-10-26 19:04:23.415 DNS     192.168.1.105:54321       8.8.8.8:53                56B    Query="google.com"
   ```
5. **Option 5**: Filter captured records dynamically by protocol (`TCP`, `UDP`, `DNS`, `ICMP`, `ARP`).
6. **Option 6**: View aggregate traffic volume, protocol breakdown percentages, and top 5 communicating hosts.
7. **Option 7**: Export to timestamped CSV under `output/capture_YYYYMMDD_HHMMSS.csv`.
8. **Option 8**: Clear memory buffer for a fresh session.
9. **Option 9**: Safely shut down background threads and exit.

*(Offline Demonstration Tip: Type `demo` at the main menu prompt to load sample synthetic packets into memory for demonstration purposes without requiring live network sockets).*

---

## 7. Testing Suite

Run the automated synthetic packet test suite without requiring root/administrator rights or live network traffic:

```powershell
py test_sniffer.py
```

### Automated Test Coverage:
- `test_ipv4_tcp_parsing`: Header parsing, TCP ports, flags (`SYN, ACK`), lengths.
- `test_ipv6_udp_parsing`: IPv6 addresses and UDP transport layer dissection.
- `test_icmp_parsing`: ICMP echo inspection and graceful `N/A` port fallback.
- `test_dns_query_parsing`: DNS query extraction from PacketListField.
- `test_missing_ip_and_ports_arp`: Non-IP ARP frame handling.
- `test_non_ip_raw_frame`: Generic raw frame handling without crashes.
- `test_empty_capture_statistics`: Graceful handling of zero packets in memory.
- `test_statistics_aggregation`: Protocol counts, top source/dest IPs, byte totals.
- `test_protocol_filtering`: Protocol-based filtering accuracy.
- `test_pandas_csv_export`: Pandas DataFrame generation and CSV file verification.
- `test_empty_pandas_csv_export`: Proper CSV generation with headers when capture is empty.

---

## 8. Common Errors & Troubleshooting

| Error Message | Root Cause | Solution |
| :--- | :--- | :--- |
| `RuntimeError: winpcap is not installed` | Windows does not have Npcap installed or running. | Install Npcap from [npcap.com](https://npcap.com/#download). Make sure **"Install Npcap in WinPcap API-compatible Mode"** is checked. |
| `PermissionError: [WinError 10013]` / `OSError: usable as administrator` | Opening raw sockets on Windows requires elevated privileges. | Right-click PowerShell or Windows Terminal and select **"Run as Administrator"**, or use Npcap. |
| `File ... Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell default Execution Policy blocks external `.ps1` scripts. | Do not compromise system security. Simply call the Python virtual environment executable directly: `.\.venv\Scripts\python.exe main.py`. |
| `ModuleNotFoundError: No module named 'scapy'` | Dependencies are not installed in the active environment. | Run `py -m pip install -r requirements.txt`. |
| `No packets captured on selected interface` | Traffic is flowing over a different interface (e.g. Wi-Fi vs Ethernet) or BPF filter is too restrictive. | Use Option 1 to verify active interface IP, or choose `0` for default auto-detection. Open a browser and visit an HTTP/HTTPS site to generate traffic. |

---

## 9. Safety, Privacy & Ethical Guidelines

This tool is strictly designed for **educational, defensive, and authorized administrative network monitoring**:
- **Metadata Only**: The sniffer extracts only standard packet headers (IP addresses, ports, protocols, flags, query names). It **never** extracts, inspects, or logs raw application payloads, private messages, session tokens, or credentials.
- **Authorized Scope**: Monitor only network interfaces that you own or have explicit administrative authorization to monitor.
- **Encryption Integrity**: Modern web traffic relies on TLS/HTTPS (port 443). The sniffer confirms communication endpoints and packet volume but cannot and does not attempt to decrypt application contents.
- **No External Exfiltration**: All captured metadata remains strictly local in memory or saved to the local `output/` directory upon user request.

---

## 10. College Project Demonstration Script

When demonstrating this project to instructors or peers:
1. **Explain the Purpose**: Explain that network packet sniffers are fundamental tools in network engineering, defensive security, and incident response for understanding traffic patterns and detecting anomalies.
2. **Demonstrate Interface Enumeration**: Select Option 1 to show how Scapy interacts with Windows network drivers to identify network cards (Wi-Fi, Ethernet, Loopback).
3. **Show Asynchronous Sniffing**: Select Option 2, start capturing, and note that the main menu remains responsive because packet capture runs in an isolated background thread (`packet_capture.py`).
4. **Inspect Dissected Headers**: Select Option 4 to show dissected packets (TCP flags like `SYN/ACK`, DNS query domains, ports).
5. **Show Protocol Filtering**: Select Option 5 and filter by `DNS` or `TCP` to showcase query filtering.
6. **Show Analytics & Export**: Select Option 6 for volume breakdown and top communicating IPs, then Option 7 to generate a clean CSV file using **Pandas**.
7. **Highlight Safe Architecture**: Emphasize that privacy was maintained by omitting raw payload extraction and adhering to defensive cybersecurity principles.
