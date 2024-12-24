from pathlib import Path
from typing import Optional, List, Callable
from datetime import datetime
import logging
import asyncio
from scapy.all import PcapWriter, wrpcap, AsyncSniffer
from scapy.packet import Packet

class AsyncPCAPWriter:
    """Asynchronous PCAP capture and writing."""
    def __init__(self, base_dir: Path, prefix: str = "capture"):
        self.base_dir = base_dir
        self.prefix = prefix
        self.logger = logging.getLogger(__name__)
        self.pcap_writer: Optional[PcapWriter] = None
        self.current_file: Optional[Path] = None
        self.packets: List[Packet] = []
        self.sniffer: Optional[AsyncSniffer] = None
        self._started = asyncio.Event()
        self._stopping = False
        self._packet_count = 0

    async def start(self, 
                   interface: str, 
                   filter_str: str, 
                   callback: Optional[Callable[[Packet], None]] = None) -> bool:
        """Initialize PCAP capture asynchronously."""
        try:
            # Ensure directory exists
            self.base_dir.mkdir(parents=True, exist_ok=True)
            
            # Create unique filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.current_file = self.base_dir / f"{self.prefix}_{timestamp}.pcap"
            
            def packet_handler(packet: Packet):
                if self._stopping:
                    return
                
                self._packet_count += 1
                self.packets.append(packet)
                if callback:
                    callback(packet)
                
                # Periodically flush packets to disk
                if self._packet_count % 1000 == 0:
                    self._write_packets()
                    self.logger.debug(f"Captured {self._packet_count} packets")

            self.logger.debug(f"Starting PCAP capture on {interface} with filter: {filter_str}")
            self.sniffer = AsyncSniffer(
                iface=interface,
                filter=filter_str,
                prn=packet_handler,
                store=False
            )
            self.sniffer.start()
            
            await asyncio.sleep(0.1)  # Wait for sniffer to start
            self._started.set()
            self.logger.info(f"Started PCAP capture: {self.current_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start PCAP capture: {e}")
            return False

    def _write_packets(self) -> None:
        """Write accumulated packets to disk."""
        if self.packets:
            try:
                wrpcap(str(self.current_file), self.packets, append=True)
                self.packets = []  # Clear after successful write
            except Exception as e:
                self.logger.error(f"Error writing packets to PCAP: {e}")

    async def wait_started(self) -> None:
        """Wait for the capture to start."""
        await self._started.wait()

    async def stop(self) -> Optional[Path]:
        """Stop PCAP capture and save to file."""
        if not self.sniffer:
            return None

        try:
            self._stopping = True
            self.logger.debug("Stopping PCAP capture...")
            
            # Stop the sniffer
            self.sniffer.stop()
            
            # Wait a bit to ensure all packets are processed
            await asyncio.sleep(0.5)
            
            # Save captured packets
            if self.packets:
                self.logger.debug(f"Saving {len(self.packets)} packets to {self.current_file}")
                wrpcap(str(self.current_file), self.packets)
                self.logger.info(f"Saved PCAP capture to {self.current_file}")
                return self.current_file
            else:
                self.logger.warning("No packets captured")
                return None
                
        except Exception as e:
            self.logger.error(f"Error stopping PCAP capture: {e}")
            return None
        finally:
            self.sniffer = None
            self._started.clear()
            self._stopping = False
            self._packet_count = 0

class AsyncPCAPManager:
    """Async manager for multiple PCAP captures."""
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.writers: dict[str, AsyncPCAPWriter] = {}
        self.logger = logging.getLogger(__name__)

    async def create_capture(self, 
                           name: str, 
                           interface: str, 
                           filter_str: str,
                           prefix: str = "capture") -> Optional[AsyncPCAPWriter]:
        """Create and start a new PCAP capture."""
        try:
            capture_dir = self.base_dir / name
            writer = AsyncPCAPWriter(capture_dir, prefix)
            if await writer.start(interface, filter_str):
                self.writers[name] = writer
                return writer
            return None
        except Exception as e:
            self.logger.error(f"Failed to create capture {name}: {e}")
            return None

    async def stop_capture(self, name: str) -> Optional[Path]:
        """Stop a specific capture."""
        if writer := self.writers.get(name):
            result = await writer.stop()
            del self.writers[name]
            return result
        return None

    async def stop_all(self) -> List[Path]:
        """Stop all active captures."""
        results = []
        for name in list(self.writers.keys()):
            if result := await self.stop_capture(name):
                results.append(result)
        return results 