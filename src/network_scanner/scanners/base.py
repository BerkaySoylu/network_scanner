# src/network_scanner/scanners/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from ..network.packet import PacketInfo
import logging
from pathlib import Path

@dataclass
class PortResult:
    port: int
    state: str
    service: Optional[str] = None
    reason: Optional[str] = None
    ttl: Optional[int] = None
    version: Optional[str] = None

class BaseScanner(ABC):
    """Abstract base class for implementing different port scanning techniques.

    This class defines the interface that all scanner implementations must follow.
    It provides common functionality for service detection and resource management.

    Args:
        target (str): Target IP address or hostname
        source_ip (str): Source IP address for scanning
        interface (str): Network interface to use
        pcap_dir (Optional[Path]): Directory for PCAP capture files

    Note:
        Implementations should handle their own packet crafting and response processing
        while adhering to the common interface defined here.
    """
    def __init__(self, target: str, source_ip: str, interface: str, pcap_dir: Optional[Path] = None):
        self.target = target
        self.source_ip = source_ip
        self.interface = interface
        self.pcap_dir = pcap_dir
        self.logger = logging.getLogger(self.__class__.__name__)
        
    @abstractmethod
    async def scan_port(self, port: int) -> PortResult:
        """Scan a single port."""
        pass

    def get_service_name(self, port: int) -> Optional[str]:
        """Get service name for a port."""
        from ..config.constants import PORT_SERVICES
        return PORT_SERVICES.get(port)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
        
    async def cleanup(self) -> None:
        """Cleanup resources."""
        pass
