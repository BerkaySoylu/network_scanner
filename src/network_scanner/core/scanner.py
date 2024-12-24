# src/network_scanner/core/scanner.py
from typing import List, Dict, Optional, Type, Union
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import logging
from contextlib import AsyncExitStack
from pathlib import Path

from ..network.interface import NetworkInterface
from ..network.sniffer import NetworkSniffer
from ..scanners.base import BaseScanner, PortResult
from ..scanners.tcp_scanner import TCPConnectScanner
from ..scanners.syn_scanner import SYNScanner
from ..scanners.udp_scanner import UDPScanner
from ..config.settings import ScannerSettings
from .discovery import HostDiscovery
from .fingerprint import OSFingerprinter
from .rate_limiter import RateLimiter

@dataclass
class ScanResult:
    """Container for network scan results.

    Attributes:
        target (str): The scanned target (IP or hostname)
        timestamp (datetime): When the scan was performed
        status (str): Target status ("up", "down", or "unknown")
        os_info (Optional[str]): Detected operating system information
        ttl (Optional[int]): Time-to-live value from responses
        ports (List[Dict]): List of scanned port results
        statistics (Dict): Scan statistics including open/closed/filtered counts
    """
    target: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    status: str = "unknown"
    os_info: Optional[str] = None
    ttl: Optional[int] = None
    ports: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=lambda: {
        "open": 0,
        "closed": 0,
        "filtered": 0,
        "total_scanned": 0
    })

class NetworkScanner:
    """Main network scanning orchestrator that coordinates different scanning techniques.

    This class provides high-level scanning functionality by combining host discovery,
    OS fingerprinting, and port scanning capabilities. It supports multiple scanning
    methods including TCP Connect, SYN, and UDP scans.

    Attributes:
        settings (ScannerSettings): Configuration settings for the scanner
        verbose (bool): Enable verbose logging output
        dev_mode (bool): Enable development mode with additional debugging
        pcap_dir (Optional[Path]): Directory for storing PCAP capture files

    Example:
        ```python
        from network_scanner import NetworkScanner, ScannerSettings

        settings = ScannerSettings()
        scanner = NetworkScanner(settings)
        
        async with scanner:
            result = await scanner.scan("192.168.1.1", ports=[80, 443], scan_types=["tcp"])
        ```
    """
    def __init__(
        self,
        settings: Optional[ScannerSettings] = None,
        verbose: bool = False,
        dev_mode: bool = False,
        pcap_dir: Optional[Path] = None
    ):
        self.settings = settings or ScannerSettings()
        self.verbose = verbose
        self.dev_mode = dev_mode
        self.pcap_dir = pcap_dir
        self.logger = self._setup_logging()
        self.interface = NetworkInterface()
        self.scan_results = ScanResult("")
        self._rate_limiter = RateLimiter(self.settings.get_timing_delay())
        self._semaphore = asyncio.Semaphore(self.settings.max_concurrent_scans)
        self.sniffer: Optional[NetworkSniffer] = None
        
        # Scanner mapping
        self.scanner_types = {
            "tcp": TCPConnectScanner,
            "syn": SYNScanner,
            "udp": UDPScanner
        }

    def _setup_logging(self) -> logging.Logger:
        """Configure logging based on verbosity."""
        logger = logging.getLogger(__name__)
        level = logging.DEBUG if self.dev_mode else (
            logging.INFO if self.verbose else logging.WARNING
        )
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
        
        return logger

    async def initialize(self) -> bool:
        """Initialize scanner and network interface."""
        try:
            if not self.interface.initialize():
                self.logger.error("Failed to initialize network interface")
                return False
                
            self.logger.info(f"Initialized scanner on interface {self.interface.interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization error: {e}")
            return False

    async def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scan_types: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Perform a complete network scan on the target.
        """
        async with AsyncExitStack() as stack:
            try:
                if not await self.initialize():
                    raise Exception("Scanner initialization failed")

                self.scan_results = ScanResult(target)
                scan_types = scan_types or ["tcp"]
                ports = ports or self.settings.default_ports

                # Create PCAP directory if specified
                scan_pcap_dir = None
                if self.settings.save_pcap:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    scan_pcap_dir = self.settings.pcap_dir / f"scan_{timestamp}"
                    scan_pcap_dir.mkdir(parents=True, exist_ok=True)
                    self.logger.info(f"Created PCAP directory: {scan_pcap_dir}")
                    
                    # Initialize sniffer with pcap_dir
                    self.sniffer = NetworkSniffer(
                        interface=self.interface.interface,
                        pcap_dir=scan_pcap_dir
                    )
                    
                    # Start sniffer with just the filter string
                    await self.sniffer.start(
                        filter_str=f"host {target}"
                    )

                # Perform host discovery with PCAP
                discovery = await stack.enter_async_context(HostDiscovery(
                    target,
                    self.interface.src_ip,
                    self.interface.interface
                ))
                if not await discovery.check_host():
                    self.scan_results.status = "down"
                    return self.scan_results

                self.scan_results.status = "up"

                # Perform OS fingerprinting with PCAP
                fingerprinter = await stack.enter_async_context(OSFingerprinter(
                    target,
                    self.interface.src_ip,
                    self.interface.interface
                ))
                os_info = await fingerprinter.detect_os()
                self.scan_results.os_info = os_info.os_name
                self.scan_results.ttl = os_info.ttl

                # Perform port scans with PCAP
                for scan_type in scan_types:
                    if scan_type not in self.scanner_types:
                        self.logger.warning(f"Unsupported scan type: {scan_type}")
                        continue

                    scanner_class = self.scanner_types[scan_type]
                    scanner = await stack.enter_async_context(scanner_class(
                        target,
                        self.interface.src_ip,
                        self.interface.interface,
                        timeout=self.settings.default_timeout,
                        pcap_dir=scan_pcap_dir
                    ))

                    results = await self._scan_ports(scanner, ports)
                    self._process_results(results)

                # Stop packet capture if it was started
                if self.sniffer:
                    await self.sniffer.stop()
                    self.logger.info("Packet capture completed")

                return self.scan_results

            except Exception as e:
                self.logger.error(f"Scan error: {e}")
                if self.dev_mode:
                    self.logger.exception("Full traceback:")
                raise
            finally:
                # Ensure sniffer is stopped even if an error occurs
                if hasattr(self, 'sniffer') and self.sniffer:
                    await self.sniffer.stop()

    async def __aenter__(self):
        await self.initialize()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()

    async def scan_port_with_limit(self, scanner: BaseScanner, port: int) -> PortResult:
        """Scan a single port with rate limiting and concurrency control."""
        async with self._semaphore:
            await self._rate_limiter.acquire()
            return await scanner.scan_port(port)

    async def _scan_ports(self, scanner: BaseScanner, ports: List[int]) -> List[PortResult]:
        """Scan ports with improved concurrency control."""
        tasks = [
            self.scan_port_with_limit(scanner, port)
            for port in ports
        ]
        
        results = []
        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                results.append(result)
            except Exception as e:
                self.logger.error(f"Port scan error: {e}")
                if self.dev_mode:
                    self.logger.exception("Full traceback:")
                
        return results

    def _process_results(self, results: List[PortResult]) -> None:
        """Process and store scan results."""
        for result in results:
            port_info = {
                "port": result.port,
                "state": result.state,
                "service": result.service,
                "reason": result.reason
            }
            if result.ttl:
                port_info["ttl"] = result.ttl
            if result.version:
                port_info["version"] = result.version

            self.scan_results.ports.append(port_info)
            
            # Update statistics
            if result.state == "open":
                self.scan_results.statistics["open"] += 1
            elif result.state == "closed":
                self.scan_results.statistics["closed"] += 1
            elif "filtered" in result.state:
                self.scan_results.statistics["filtered"] += 1
                
            self.scan_results.statistics["total_scanned"] += 1

    async def stop(self) -> None:
        """Stop all scanning operations."""
        # Implementation for stopping ongoing scans
        pass
