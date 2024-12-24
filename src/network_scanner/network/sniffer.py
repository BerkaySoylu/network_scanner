# src/network_scanner/network/sniffer.py
from typing import Optional, Callable
from scapy.all import AsyncSniffer
from scapy.packet import Packet
import logging
from pathlib import Path
from .packet import PacketHandler, PacketInfo
from .pcap import AsyncPCAPWriter
from datetime import datetime

class NetworkSniffer:
    def __init__(self, interface: str, pcap_dir: Optional[Path] = None):
        self.interface = interface
        self.pcap_dir = pcap_dir
        self.logger = logging.getLogger(__name__)
        self.sniffer: Optional[AsyncSniffer] = None
        self.packet_handler = PacketHandler()
        self._stopping = False
        self.pcap_writer: Optional[AsyncPCAPWriter] = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
        return None

    async def start(self, 
                   filter_str: str, 
                   callback: Optional[Callable[[PacketInfo], None]] = None) -> None:
        """Start packet capture with optional PCAP recording."""
        try:
            # Initialize PCAP capture if directory is specified
            if self.pcap_dir:
                self.pcap_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.pcap_writer = AsyncPCAPWriter(self.pcap_dir, f"capture_{timestamp}")
                
                success = await self.pcap_writer.start(
                    self.interface, 
                    filter_str
                )
                
                if not success:
                    self.logger.error("Failed to start PCAP capture")
                    self.pcap_writer = None
                else:
                    await self.pcap_writer.wait_started()
                    self.logger.info(f"PCAP capture started in {self.pcap_dir}")

            def packet_callback(packet: Packet) -> None:
                if self._stopping:
                    return

                # Always send to PCAP writer if available
                if self.pcap_writer:
                    self.pcap_writer.packets.append(packet)

                # Process packet and call user callback
                packet_info = self.packet_handler.analyze_packet(packet)
                if packet_info and callback:
                    callback(packet_info)

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=filter_str,
                prn=packet_callback,
                store=False
            )
            
            self.logger.debug(f"Starting sniffer on {self.interface} with filter: {filter_str}")
            self.sniffer.start()

        except Exception as e:
            self.logger.error(f"Error starting sniffer: {e}")
            raise

    async def stop(self) -> Optional[Path]:
        """Stop packet capture and cleanup resources."""
        self._stopping = True
        pcap_file = None
        
        try:
            if self.sniffer and self.sniffer.running:
                self.logger.debug("Stopping packet sniffer...")
                self.sniffer.stop()
                
            if self.pcap_writer:
                self.logger.debug("Stopping PCAP capture...")
                pcap_file = await self.pcap_writer.stop()
                if pcap_file:
                    self.logger.info(f"PCAP file saved: {pcap_file}")
                self.pcap_writer = None
                
        finally:
            self._stopping = False
            self.logger.debug("Sniffer stopped")
            return pcap_file
