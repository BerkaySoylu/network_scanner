# src/network_scanner/scanners/syn_scanner.py
from typing import Optional
from pathlib import Path
import asyncio
import logging
from datetime import datetime
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1
from .base import BaseScanner, PortResult
from ..network.sniffer import NetworkSniffer

class SYNScanner(BaseScanner):
    def __init__(self, target: str, source_ip: str, interface: str, timeout: float = 2.0, pcap_dir: Optional[Path] = None):
        super().__init__(target, source_ip, interface, pcap_dir)
        self.timeout = timeout
        self.sniffer: Optional[NetworkSniffer] = None

    async def scan_port(self, port: int) -> PortResult:
        """Perform a SYN scan on a port."""
        try:
            # Create SYN packet
            syn_packet = IP(src=self.source_ip, dst=self.target)/TCP(
                dport=port,
                flags="S",
                seq=1000
            )

            # Send packet and wait for response
            loop = asyncio.get_event_loop()
            reply = await loop.run_in_executor(
                None,
                lambda: sr1(syn_packet, timeout=self.timeout, verbose=0)
            )

            if reply and TCP in reply:
                flags = reply[TCP].flags
                if flags & 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(src=self.source_ip, dst=self.target)/TCP(
                        dport=port,
                        flags="R",
                        seq=reply[TCP].ack
                    )
                    await loop.run_in_executor(None, lambda: sr1(rst_packet, timeout=1, verbose=0))
                    
                    return PortResult(
                        port=port,
                        state="open",
                        service=self.get_service_name(port),
                        reason="syn-ack",
                        ttl=reply[IP].ttl
                    )
                elif flags & 0x14:  # RST-ACK
                    return PortResult(
                        port=port,
                        state="closed",
                        service=self.get_service_name(port),
                        reason="rst-ack",
                        ttl=reply[IP].ttl
                    )

            return PortResult(
                port=port,
                state="filtered",
                service=self.get_service_name(port),
                reason="no-response"
            )

        except Exception as e:
            self.logger.error(f"Error during SYN scan of port {port}: {e}")
            return PortResult(
                port=port,
                state="error",
                service=self.get_service_name(port),
                reason=str(e)
            )

    async def __aenter__(self):
        """Set up sniffer if PCAP capture is enabled."""
        if self.pcap_dir:
            scan_dir = self.pcap_dir / f"syn_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            scan_dir.mkdir(parents=True, exist_ok=True)
            
            self.sniffer = NetworkSniffer(self.interface, pcap_dir=scan_dir)
            filter_str = f"tcp and host {self.target}"
            await self.sniffer.start(
                filter_str=filter_str
            )
            self.logger.debug(f"Started packet capture in {scan_dir}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up sniffer if it was used."""
        if self.sniffer:
            await self.sniffer.stop()
            self.sniffer = None

    async def cleanup(self) -> None:
        """Ensure sniffer is stopped."""
        if self.sniffer:
            await self.sniffer.stop()
            self.sniffer = None
