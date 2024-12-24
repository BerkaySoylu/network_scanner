# src/network_scanner/scanners/tcp_scanner.py
from .base import BaseScanner, PortResult
import socket
import asyncio
from typing import Optional
from pathlib import Path
from ..network.sniffer import NetworkSniffer
from datetime import datetime
import logging

class TCPConnectScanner(BaseScanner):
    def __init__(self, target: str, source_ip: str, interface: str, timeout: float = 2.0, pcap_dir: Optional[Path] = None):
        super().__init__(target, source_ip, interface, pcap_dir)
        self.timeout = timeout
        self.sniffer: Optional[NetworkSniffer] = None

    async def scan_port(self, port: int) -> PortResult:
        """Perform a TCP connect scan on a port."""
        sock = None
        try:
            # Create socket and set timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Convert to coroutine
            loop = asyncio.get_event_loop()
            await loop.sock_connect(sock, (self.target, port))
            
            # Try to get service banner
            version = ""
            try:
                # Set shorter timeout for banner grab
                sock.settimeout(1.0)
                
                # Send appropriate probe based on port
                if port in {80, 443}:
                    await loop.sock_sendall(sock, b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 22:
                    # SSH usually sends banner immediately, no need to probe
                    pass
                else:
                    await loop.sock_sendall(sock, b"\r\n")
                
                # Read response with timeout
                banner = await asyncio.wait_for(
                    loop.sock_recv(sock, 1024),
                    timeout=1.0
                )
                version = banner.decode('utf-8', 'ignore').strip()
                
            except (socket.timeout, UnicodeDecodeError, asyncio.TimeoutError) as e:
                self.logger.debug(f"Failed to get banner for port {port}: {e}")
            
            finally:
                # Always return open state if we got this far
                return PortResult(
                    port=port,
                    state="open",
                    service=self.get_service_name(port),
                    version=version,
                    reason="connect-success"
                )
                
        except socket.timeout:
            return PortResult(
                port=port,
                state="filtered",
                service=self.get_service_name(port),
                reason="timeout"
            )
        except ConnectionRefusedError:
            return PortResult(
                port=port,
                state="closed",
                service=self.get_service_name(port),
                reason="connection-refused"
            )
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return PortResult(
                port=port,
                state="error",
                service=self.get_service_name(port),
                reason=str(e)
            )
        finally:
            if sock:
                sock.close()

    async def __aenter__(self):
        """Initialize scanner resources."""
        if self.pcap_dir:
            scan_dir = self.pcap_dir / f"tcp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            scan_dir.mkdir(parents=True, exist_ok=True)
            
            self.sniffer = NetworkSniffer(self.interface, pcap_dir=scan_dir)
            filter_str = f"host {self.target}"
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
