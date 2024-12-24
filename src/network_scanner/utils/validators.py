# src/network_scanner/utils/validators.py
from typing import Union, List, Optional
import ipaddress
import re
import socket
from dataclasses import dataclass

@dataclass
class ValidationResult:
    is_valid: bool
    message: Optional[str] = None
    value: Optional[str] = None

class InputValidator:
    @staticmethod
    def validate_ip_or_hostname(target: str) -> ValidationResult:
        """Validate IP address or hostname."""
        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(target)
            return ValidationResult(
                is_valid=True,
                value=str(ip)
            )
        except ValueError:
            # Check if it's a valid hostname
            if InputValidator.is_valid_hostname(target):
                try:
                    ip = socket.gethostbyname(target)
                    return ValidationResult(
                        is_valid=True,
                        value=ip
                    )
                except socket.gaierror:
                    return ValidationResult(
                        is_valid=False,
                        message=f"Could not resolve hostname: {target}"
                    )
            return ValidationResult(
                is_valid=False,
                message=f"Invalid IP address or hostname: {target}"
            )

    @staticmethod
    def validate_ports(ports: Union[str, List[int]]) -> ValidationResult:
        """Validate port numbers or port ranges."""
        if isinstance(ports, str):
            try:
                port_list = []
                for part in ports.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        if start > end:
                            return ValidationResult(
                                is_valid=False,
                                message=f"Invalid port range: {start}-{end}"
                            )
                        port_list.extend(range(start, end + 1))
                    else:
                        port = int(part)
                        port_list.append(port)
                
                # Validate port numbers
                for port in port_list:
                    if not 0 <= port <= 65535:
                        return ValidationResult(
                            is_valid=False,
                            message=f"Port number out of range: {port}"
                        )
                
                return ValidationResult(
                    is_valid=True,
                    value=port_list
                )
            except ValueError:
                return ValidationResult(
                    is_valid=False,
                    message="Invalid port specification"
                )
        
        # If ports is already a list
        if all(isinstance(p, int) and 0 <= p <= 65535 for p in ports):
            return ValidationResult(
                is_valid=True,
                value=ports
            )
        return ValidationResult(
            is_valid=False,
            message="Invalid port list"
        )

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Check if a hostname is valid."""
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    @staticmethod
    def validate_scan_type(scan_type: str) -> ValidationResult:
        """Validate scan type."""
        valid_types = {"tcp", "syn", "udp", "ack"}
        if scan_type.lower() in valid_types:
            return ValidationResult(
                is_valid=True,
                value=scan_type.lower()
            )
        return ValidationResult(
            is_valid=False,
            message=f"Invalid scan type. Must be one of: {', '.join(valid_types)}"
        )
