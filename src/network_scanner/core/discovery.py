# src/network_scanner/core/discovery.py
from dataclasses import dataclass
from typing import Optional
import asyncio
import logging
from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import sr1
from ..network.sniffer import NetworkSniffer

@dataclass
class HostStatus:
    is_up: bool
    method: Optional[str] = None
    ttl: Optional[int] = None

class HostDiscovery:
    def __init__(self, target: str, source_ip: str, interface: str):
        self.target = target
        self.source_ip = source_ip
        self.interface = interface
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        # Cleanup if needed
        pass

    async def check_host(self) -> bool:
        """
        Check if host is up using multiple methods:
        1. ICMP echo request
        2. TCP SYN to port 443
        3. TCP ACK to port 80
        """
        methods = [
            self._icmp_ping,
            self._tcp_syn_ping,
            self._tcp_ack_ping
        ]

        for method in methods:
            try:
                result = await method()
                if result.is_up:
                    self.logger.info(
                        f"Host is up ({result.method}, ttl={result.ttl})"
                    )
                    return True
            except Exception as e:
                self.logger.debug(f"Method {method.__name__} failed: {e}")
                continue

        self.logger.info(f"Host {self.target} appears to be down")
        return False

    async def _icmp_ping(self) -> HostStatus:
        """Send ICMP echo request."""
        loop = asyncio.get_event_loop()
        packet = IP(src=self.source_ip, dst=self.target)/ICMP()
        
        try:
            reply = await loop.run_in_executor(
                None,
                lambda: sr1(packet, timeout=2, verbose=0)
            )
        except Exception as e:
            self.logger.debug(f"ICMP ping failed: {e}")
            return HostStatus(is_up=False)

        if reply and ICMP in reply:
            return HostStatus(
                is_up=True,
                method="ICMP echo reply",
                ttl=reply.ttl
            )
            
        return HostStatus(is_up=False)

    async def _tcp_syn_ping(self) -> HostStatus:
        """Send TCP SYN packet to port 443."""
        loop = asyncio.get_event_loop()
        packet = IP(src=self.source_ip, dst=self.target)/TCP(
            dport=443,
            flags="S"
        )
        
        reply = await loop.run_in_executor(
            None,
            lambda: sr1(packet, timeout=2, verbose=0)
        )

        if reply and TCP in reply:
            return HostStatus(
                is_up=True,
                method="TCP SYN response",
                ttl=reply.ttl
            )
            
        return HostStatus(is_up=False)

    async def _tcp_ack_ping(self) -> HostStatus:
        """Send TCP ACK packet to port 80."""
        loop = asyncio.get_event_loop()
        packet = IP(src=self.source_ip, dst=self.target)/TCP(
            dport=80,
            flags="A"
        )
        
        reply = await loop.run_in_executor(
            None,
            lambda: sr1(packet, timeout=2, verbose=0)
        )

        if reply and TCP in reply:
            return HostStatus(
                is_up=True,
                method="TCP ACK response",
                ttl=reply.ttl
            )
            
        return HostStatus(is_up=False)
