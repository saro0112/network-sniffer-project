"""
packet_capture.py
=================
Threaded packet capture module using Scapy for Windows and cross-platform systems.
Handles network interface discovery, background sniffing, safe start/stop controls,
and thread-safe packet storage.
"""

import threading
import time
import logging
from typing import List, Dict, Any, Optional, Callable

# Suppress noisy Scapy runtime logs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from packet_analyzer import analyze_packet


class PacketCaptureEngine:
    """
    Manages asynchronous packet sniffing using Scapy in a dedicated worker thread.
    Maintains thread-safe packet records and cleanly handles capture lifecycle.
    """

    def __init__(self, on_packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        """
        Initialize the packet capture engine.
        
        Args:
            on_packet_callback: Optional function called whenever a packet is parsed.
        """
        self._on_packet_callback = on_packet_callback
        self._captured_packets: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        self._is_running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        self._active_interface: Optional[str] = None
        self._active_filter: Optional[str] = None
        self._last_error: Optional[str] = None

    @property
    def is_running(self) -> bool:
        """Check if packet capture is currently active."""
        return self._is_running

    @property
    def active_interface(self) -> Optional[str]:
        """Return the name or description of the current interface."""
        return self._active_interface

    @property
    def last_error(self) -> Optional[str]:
        """Return the most recent error message, if any."""
        return self._last_error

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """
        Discover and list available network interfaces.
        
        Returns:
            List of dictionaries containing interface metadata (index, name, description, ip, mac).
        """
        interfaces = []
        try:
            from scapy.all import conf

            # Inspect Scapy's conf.ifaces
            for idx, dev in enumerate(conf.ifaces.values()):
                name = getattr(dev, "name", f"Interface {idx}")
                desc = getattr(dev, "description", "")
                ip = getattr(dev, "ip", "") or ""
                mac = getattr(dev, "mac", "") or ""
                dev_id = getattr(dev, "guid", None) or getattr(dev, "network_name", None) or name

                interfaces.append({
                    "index": idx + 1,
                    "name": name,
                    "description": desc or name,
                    "ip": ip,
                    "mac": mac,
                    "scapy_dev": dev,
                })
        except Exception as e:
            # Fallback for bare systems
            interfaces.append({
                "index": 1,
                "name": "Default / Auto",
                "description": f"Default System Interface (Error querying: {e})",
                "ip": "N/A",
                "mac": "N/A",
                "scapy_dev": None,
            })

        return interfaces

    def start_capture(self, scapy_interface: Any = None, bpf_filter: Optional[str] = None) -> bool:
        """
        Start capturing packets in a background thread.
        
        Args:
            scapy_interface: Interface object, name, or None for default.
            bpf_filter: Optional Berkeley Packet Filter (BPF) string (e.g. 'tcp', 'udp', 'port 53').
            
        Returns:
            True if capture started, False if already running or start failed.
        """
        if self._is_running:
            self._last_error = "Packet capture is already running."
            return False

        self._last_error = None
        self._stop_event.clear()
        self._is_running = True
        self._active_interface = getattr(scapy_interface, "description", None) or getattr(scapy_interface, "name", None) or str(scapy_interface or "Default (Auto)")
        self._active_filter = bpf_filter

        self._worker_thread = threading.Thread(
            target=self._capture_worker,
            args=(scapy_interface, bpf_filter),
            daemon=True,
            name="PacketCaptureWorker"
        )
        self._worker_thread.start()
        return True

    def stop_capture(self) -> bool:
        """
        Signal the capture thread to stop and wait for clean shutdown.
        
        Returns:
            True if stopped cleanly.
        """
        if not self._is_running:
            return False

        self._stop_event.set()
        self._is_running = False

        if self._worker_thread and self._worker_thread.is_alive():
            # Wait up to 2.5 seconds for clean thread termination
            self._worker_thread.join(timeout=2.5)

        self._worker_thread = None
        return True

    def _capture_worker(self, scapy_iface: Any, bpf_filter: Optional[str]) -> None:
        """
        Worker loop running in a background thread.
        Uses short timeouts to remain responsive to stop signals.
        """
        from scapy.all import sniff, conf

        def packet_handler(pkt: Any) -> None:
            """Process individual packets received from Scapy."""
            with self._lock:
                pkt_num = len(self._captured_packets) + 1
                parsed = analyze_packet(pkt, packet_number=pkt_num)
                self._captured_packets.append(parsed)

            if self._on_packet_callback:
                try:
                    self._on_packet_callback(parsed)
                except Exception:
                    pass

        try:
            # Sniff loop using timeout=1 so stop_event is checked promptly
            while not self._stop_event.is_set():
                sniff_kwargs: Dict[str, Any] = {
                    "prn": packet_handler,
                    "store": False,
                    "timeout": 1,
                    "stop_filter": lambda p: self._stop_event.is_set(),
                }
                if scapy_iface is not None:
                    sniff_kwargs["iface"] = scapy_iface
                if bpf_filter:
                    sniff_kwargs["filter"] = bpf_filter

                try:
                    sniff(**sniff_kwargs)
                except RuntimeError as rerr:
                    err_msg = str(rerr)
                    if "winpcap is not installed" in err_msg or "libpcap" in err_msg:
                        # Attempt fallback to Layer 3 socket if Npcap is missing
                        try:
                            sniff_kwargs["L2socket"] = conf.L3socket
                            sniff(**sniff_kwargs)
                        except Exception as l3_err:
                            self._last_error = (
                                "Npcap is required on Windows for packet capture.\n"
                                "Download and install Npcap from: https://npcap.com/#download\n"
                                "Note: Enable 'Install Npcap in WinPcap API-compatible Mode' during installation,\n"
                                f"or run terminal as Administrator. (Details: {l3_err})"
                            )
                            self._is_running = False
                            return
                    else:
                        raise rerr

        except PermissionError:
            self._last_error = (
                "Permission denied: Administrator privileges required.\n"
                "On Windows, opening raw network sockets requires running PowerShell/Terminal as Administrator,\n"
                "or having Npcap installed with WinPcap API compatibility."
            )
        except OSError as ose:
            self._last_error = (
                f"Network socket error: {ose}\n"
                "Ensure Npcap is installed and you have sufficient permissions to capture network packets."
            )
        except Exception as e:
            self._last_error = f"Unexpected error during packet capture: {e}"
        finally:
            self._is_running = False

    def get_packets(self) -> List[Dict[str, Any]]:
        """Return a copy of all captured packet metadata records."""
        with self._lock:
            return list(self._captured_packets)

    def get_packet_count(self) -> int:
        """Return the number of captured packets in memory."""
        with self._lock:
            return len(self._captured_packets)

    def clear_packets(self) -> None:
        """Clear the captured packet history buffer."""
        with self._lock:
            self._captured_packets.clear()

    def add_synthetic_packet(self, packet_dict: Dict[str, Any]) -> None:
        """Add a synthetic or pre-parsed packet record (useful for testing and demos)."""
        with self._lock:
            packet_dict["packet_number"] = len(self._captured_packets) + 1
            self._captured_packets.append(packet_dict)
