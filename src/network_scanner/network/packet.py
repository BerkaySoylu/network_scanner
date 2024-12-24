# src/network_scanner/network/packet.py
from dataclasses import dataclass
from typing import Optional, Dict, Any
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet as ScapyPacket

@dataclass
class PacketInfo:
    """Information extracted from captured network packets.

    This class provides a structured representation of packet data
    that is relevant for port scanning and OS fingerprinting.

    Attributes:
        protocol (str): Protocol name (TCP, UDP, ICMP)
        src_ip (str): Source IP address
        dst_ip (str): Destination IP address
        src_port (Optional[int]): Source port number
        dst_port (Optional[int]): Destination port number
        ttl (Optional[int]): Time-to-live value
        flags (Optional[str]): TCP flags as string
        window_size (Optional[int]): TCP window size
        data (Optional[bytes]): Raw packet payload
    """
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    ttl: Optional[int] = None
    flags: Optional[str] = None
    window_size: Optional[int] = None
    data: Optional[bytes] = None

class PacketHandler:
    @staticmethod
    def analyze_packet(packet: ScapyPacket) -> Optional[PacketInfo]:
        """Analyze a packet and return structured information."""
        if not IP in packet:
            return None

        protocol = "UNKNOWN"
        src_port = None
        dst_port = None
        flags = None

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = PacketHandler._get_tcp_flags(packet[TCP].flags)
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"

        return PacketInfo(
            src_ip=packet[IP].src,
            dst_ip=packet[IP].dst,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            ttl=packet[IP].ttl,
            data=bytes(packet.payload) if packet.payload else None
        )

    @staticmethod
    def _get_tcp_flags(flags: int) -> str:
        """Convert TCP flags to string representation."""
        flag_map = {
            0x02: "SYN",
            0x10: "ACK",
            0x04: "RST",
            0x01: "FIN",
            0x08: "PSH",
            0x20: "URG"
        }
        return "|".join(flag for flag, value in flag_map.items() if flags & value)
