"""Security Toolkit Suite.

A desktop GUI + CLI suite of cybersecurity tools organised into delivery waves.
Every tool is designed for *authorized* use only: run it only against systems
you own or have explicit written permission to test.

See README.md for the tool index and the permissions matrix.
"""

__version__ = "0.1.0"

# Canonical wave metadata used by the dashboard and docs.
WAVES = {
    1: ("W1 - Network Recon", "P0"),
    2: ("W2 - Defense & Monitoring", "P1"),
    3: ("W3 - Proxy & Tunnel", "P1"),
    4: ("W4 - Vuln Scanning", "P1"),
    5: ("W5 - Forensics", "P2"),
    6: ("W6 - Malware Analysis", "P2"),
    7: ("W7 - Red Team / C2", "P2"),
    8: ("W8 - Extras", "P3"),
}