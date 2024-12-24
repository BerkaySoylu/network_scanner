# src/network_scanner/scanners/udp_scanner.py
from typing import Optional, Dict
from pathlib import Path
import asyncio
import logging
from datetime import datetime
from scapy.layers.inet import IP, UDP, ICMP
from scapy.sendrecv import send
from .base import BaseScanner, PortResult
from ..network.sniffer import NetworkSniffer
from ..network.packet import PacketInfo

class UDPScanner(BaseScanner):
    def __init__(self, target: str, source_ip: str, interface: str, timeout: float = 5.0, pcap_dir: Optional[Path] = None):
        super().__init__(target, source_ip, interface, pcap_dir)
        self.timeout = timeout
        self.sniffer: Optional[NetworkSniffer] = None
        self._port_results: Dict[int, asyncio.Future] = {}

    async def scan_port(self, port: int) -> PortResult:
        """Perform a UDP scan on a port."""
        try:
            # Create UDP packet
            udp_packet = IP(dst=self.target)/UDP(dport=port)/b""

            # Set up response future
            self._port_results[port] = asyncio.Future()

            # Set up sniffer if not already running
            if not self.sniffer:
                self.sniffer = NetworkSniffer(self.interface)
                filter_str = f"icmp or (udp and host {self.target})"
                await self.sniffer.start(filter_str, self._handle_packet)

            # Send the UDP packet
            send(udp_packet, verbose=0)
            
            # Wait for response with timeout
            try:
                result = await asyncio.wait_for(self._port_results[port], self.timeout)
                return result
            except asyncio.TimeoutError:
                return PortResult(
                    port=port,
                    state="open|filtered",
                    service=self.get_service_name(port),
                    reason="no-response"
                )

        except Exception as e:
            self.logger.error(f"Error during UDP scan of port {port}: {e}")
            return PortResult(
                port=port,
                state="error",
                service=self.get_service_name(port),
                reason=str(e)
            )

    def _handle_packet(self, packet_info: PacketInfo) -> None:
        """Handle received packets and update port results."""
        if packet_info.protocol == "ICMP":
            # Check for ICMP port unreachable message
            if packet_info.src_ip == self.target:
                # Find the original UDP port from the ICMP payload
                # This would require deeper packet inspection
                # For now, we'll use a simplified approach
                for port in self._port_results:
                    if not self._port_results[port].done():
                        self._port_results[port].set_result(PortResult(
                            port=port,
                            state="closed",
                            service=self.get_service_name(port),
                            reason="icmp-port-unreachable",
                            ttl=packet_info.ttl
                        ))
        elif packet_info.protocol == "UDP":
            # If we get a UDP response, the port is open
            port = packet_info.src_port
            if port in self._port_results and not self._port_results[port].done():
                self._port_results[port].set_result(PortResult(
                    port=port,
                    state="open",
                    service=self.get_service_name(port),
                    reason="udp-response",
                    ttl=packet_info.ttl
                ))

    async def cleanup(self) -> None:
        """Stop sniffer and cleanup resources."""
        if self.sniffer:
            await self.sniffer.stop()
            self.sniffer = None

    async def __aenter__(self):
        """Set up sniffer if PCAP capture is enabled."""
        if self.pcap_dir:
            scan_dir = self.pcap_dir / f"udp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            scan_dir.mkdir(parents=True, exist_ok=True)
            
            self.sniffer = NetworkSniffer(self.interface, pcap_dir=scan_dir)
            filter_str = f"udp or icmp and host {self.target}"
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
