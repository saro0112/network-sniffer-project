"""
Root launcher for Network Sniffer Project.
Dispatches directly to network-sniffer-project/main.py
"""

import sys
import os

project_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network-sniffer-project")
sys.path.insert(0, project_dir)

if __name__ == "__main__":
    from main import NetworkSnifferCLI
    cli = NetworkSnifferCLI()
    cli.run()
