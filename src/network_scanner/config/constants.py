# src/network_scanner/config/constants.py
from typing import Dict, Set

# Port ranges
WELL_KNOWN_PORTS = range(1, 1024)
REGISTERED_PORTS = range(1024, 49152)
DYNAMIC_PORTS = range(49152, 65536)

# Common services and their default ports
PORT_SERVICES: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    8080: "HTTP-ALT"
}

# TCP flags
TCP_FLAGS = {
    'F': 0x01,  # FIN
    'S': 0x02,  # SYN
    'R': 0x04,  # RST
    'P': 0x08,  # PSH
    'A': 0x10,  # ACK
    'U': 0x20   # URG
}

# OS fingerprinting signatures
OS_SIGNATURES = {
    'WINDOWS': {
        'TTL': 128,
        'WINDOW_SIZE': 8192,
        'DF': 1
    },
    'LINUX': {
        'TTL': 64,
        'WINDOW_SIZE': 5840,
        'DF': 0
    }
}

# Error messages
ERROR_MESSAGES = {
    'PERMISSION_DENIED': "This scanner requires root/administrator privileges",
    'INTERFACE_NOT_FOUND': "No suitable network interface found",
    'INVALID_TARGET': "Invalid target specification",
    'SCAN_FAILED': "Scan failed to complete",
    'TIMEOUT': "Operation timed out"
}

# Exit codes
EXIT_CODES = {
    'SUCCESS': 0,
    'PERMISSION_ERROR': 1,
    'NETWORK_ERROR': 2,
    'INPUT_ERROR': 3,
    'RUNTIME_ERROR': 4
}
