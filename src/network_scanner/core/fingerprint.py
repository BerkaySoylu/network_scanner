# src/network_scanner/core/fingerprint.py
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
import asyncio
import logging
from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import sr1
from ..config.constants import OS_SIGNATURES
from ..network.packet import PacketInfo

@dataclass
class OSInfo:
    os_name: str
    ttl: int
    confidence: float
    details: Dict[str, any]
    signature_matches: List[str]

class OSFingerprinter:
    def __init__(self, target: str, source_ip: str, interface: str):
        self.target = target
        self.source_ip = source_ip
        self.interface = interface
        self.logger = logging.getLogger(__name__)
        self._probe_results: Dict[str, PacketInfo] = {}

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        # Cleanup if needed
        pass

    async def detect_os(self) -> OSInfo:
        """
        Enhanced OS detection using multiple techniques:
        1. TTL analysis
        2. TCP window size and options
        3. TCP behavior patterns
        4. ICMP response analysis
        """
        try:
            # Run all probes concurrently
            probe_tasks = [
                self._send_icmp_probe(),
                self._send_tcp_syn_probe(),
                self._send_tcp_ack_probe(),
                self._send_tcp_window_probe()
            ]
            
            await asyncio.gather(*probe_tasks)
            
            # Analyze results
            return self._analyze_probe_results()

        except Exception as e:
            self.logger.error(f"OS detection error: {e}")
            return OSInfo(
                os_name="Unknown",
                ttl=0,
                confidence=0.0,
                details={},
                signature_matches=[]
            )

    async def _send_probe(self, probe_type: str, packet: IP) -> None:
        """Generic probe sender with error handling."""
        try:
            loop = asyncio.get_event_loop()
            reply = await loop.run_in_executor(
                None,
                lambda: sr1(packet, timeout=2, verbose=0)
            )
            
            if reply:
                packet_info = PacketInfo(
                    protocol=reply.name,
                    src_ip=reply.src,
                    dst_ip=reply.dst,
                    ttl=reply.ttl,
                    flags=reply[TCP].flags if TCP in reply else None,
                    window_size=reply[TCP].window if TCP in reply else None
                )
                
                # Add TCP options if present
                if TCP in reply and hasattr(reply[TCP], 'options'):
                    packet_info.options = reply[TCP].options
                    
                self._probe_results[probe_type] = packet_info
                
        except Exception as e:
            self.logger.debug(f"Probe {probe_type} failed: {e}")

    async def _send_icmp_probe(self) -> None:
        """Send ICMP echo request probe."""
        packet = IP(src=self.source_ip, dst=self.target)/ICMP()
        await self._send_probe('icmp', packet)

    async def _send_tcp_syn_probe(self) -> None:
        """Send TCP SYN probe to common port."""
        packet = IP(src=self.source_ip, dst=self.target)/TCP(
            dport=443,
            flags="S",
            options=[('MSS', 1460), ('NOP', None), ('WScale', 7)]
        )
        await self._send_probe('tcp_syn', packet)

    async def _send_tcp_ack_probe(self) -> None:
        """Send TCP ACK probe."""
        packet = IP(src=self.source_ip, dst=self.target)/TCP(
            dport=80,
            flags="A",
            window=1024
        )
        await self._send_probe('tcp_ack', packet)

    async def _send_tcp_window_probe(self) -> None:
        """Send TCP window probe."""
        packet = IP(src=self.source_ip, dst=self.target)/TCP(
            dport=80,
            flags="S",
            window=8192
        )
        await self._send_probe('tcp_window', packet)

    def _analyze_probe_results(self) -> OSInfo:
        """Analyze all probe results to determine OS."""
        matches: Dict[str, int] = {os: 0 for os in OS_SIGNATURES.keys()}
        signature_matches: List[str] = []
        details: Dict[str, any] = {}
        ttl = 0

        # Get the most common TTL from all probes
        ttls = [result.ttl for result in self._probe_results.values() if result and result.ttl]
        if ttls:
            ttl = max(set(ttls), key=ttls.count)  # Most common TTL

        for probe_type, result in self._probe_results.items():
            if not result:
                continue

            normalized_ttl = self._normalize_ttl(ttl)
            details[probe_type] = {
                'ttl': ttl,
                'flags': result.flags,
                'window_size': result.window_size
            }

            # Match against known signatures
            for os, sig in OS_SIGNATURES.items():
                if normalized_ttl == sig['TTL']:
                    matches[os] += 2  # Give more weight to TTL matches
                    signature_matches.append(f"{os} TTL match")

                if result.window_size and result.window_size == sig['WINDOW_SIZE']:
                    matches[os] += 1
                    signature_matches.append(f"{os} window size match")

        # Determine most likely OS
        if matches:
            max_matches = max(matches.values())
            if max_matches > 0:
                os_name = max(matches.items(), key=lambda x: x[1])[0]
                confidence = min((max_matches / (len(self._probe_results) * 3)) * 100, 100)  # Scale to percentage
            else:
                os_name = "Unknown"
                confidence = 0.0
        else:
            os_name = "Unknown"
            confidence = 0.0

        return OSInfo(
            os_name=os_name,
            ttl=ttl,
            confidence=confidence,
            details=details,
            signature_matches=signature_matches
        )

    @staticmethod
    def _normalize_ttl(ttl: int) -> int:
        """Normalize TTL to closest power of 64."""
        if ttl <= 32:
            return 32
        elif ttl <= 64:
            return 64
        elif ttl <= 128:
            return 128
        else:
            return 255
