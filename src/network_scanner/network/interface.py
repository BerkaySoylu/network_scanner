# src/network_scanner/network/interface.py
from typing import Optional, List
from scapy.arch import get_if_list, get_if_addr
import socket
import logging

class NetworkInterface:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._interface: Optional[str] = None
        self._src_ip: Optional[str] = None

    def initialize(self) -> bool:
        """Initialize network interface and source IP."""
        try:
            interfaces = get_if_list()
            self.logger.debug(f"Available interfaces: {interfaces}")
            
            # Try to find working interface
            for iface in interfaces:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0' and ip != '127.0.0.1':
                    self._interface = iface
                    self._src_ip = ip
                    self.logger.info(f"Selected interface: {self._interface} ({self._src_ip})")
                    return True
            
            raise Exception("No valid network interface found")
            
        except Exception as e:
            self.logger.error(f"Error initializing interface: {e}")
            return False

    @property
    def interface(self) -> Optional[str]:
        return self._interface

    @property
    def src_ip(self) -> Optional[str]:
        return self._src_ip

    def get_local_ip(self) -> Optional[str]:
        """Get local IP address with fallback mechanisms."""
        try:
            # Primary method: Create a temporary socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            self.logger.warning(f"Primary IP detection failed: {e}")
            try:
                # Fallback 1: Try getting hostname
                local_ip = socket.gethostbyname(socket.gethostname())
                return local_ip
            except Exception as e2:
                self.logger.error(f"Fallback IP detection failed: {e2}")
                return None
