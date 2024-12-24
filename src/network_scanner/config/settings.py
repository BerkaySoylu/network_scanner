# src/network_scanner/config/settings.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Dict, List, Optional
from pathlib import Path

class ScannerSettings(BaseSettings):
    # Timing profiles (packets per second)
    timing_profiles: Dict[str, float] = {
        "paranoid": 0.5,    # 1 packet every 2 seconds
        "sneaky": 1,        # 1 packet per second
        "polite": 10,       # 10 packets per second
        "normal": 100,      # 100 packets per second
        "aggressive": 500,  # 500 packets per second
        "insane": 1000     # 1000 packets per second
    }

    # Default scan settings
    default_timeout: float = Field(default=2.0, ge=0.1)
    default_retries: int = Field(default=2, ge=0)
    default_ports: List[int] = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
    
    # Network settings
    source_port_range: tuple = (30000, 65535)
    fragment_size: int = Field(default=1400, ge=500)
    
    # Output settings
    output_dir: Path = Field(default=Path("results"))
    save_pcap: bool = Field(default=False)
    pcap_dir: Optional[Path] = Field(default=Path("pcaps"))
    store_raw_packets: bool = Field(default=False)
    max_pcap_size: int = Field(default=100 * 1024 * 1024)  # 100MB
    pcap_rotation_count: int = Field(default=5)
    
    # Advanced settings
    dev_mode: bool = False
    max_concurrent_scans: int = Field(default=100, ge=1)
    connection_timeout: float = Field(default=5.0, ge=0.1)
    
    # Packet capture settings
    capture_timeout: float = Field(default=30.0)
    capture_filter: str = Field(default="")
    
    class Config:
        env_prefix = "SCANNER_"

    def get_timing_delay(self, profile: str = "normal") -> float:
        """Get delay between packets based on timing profile."""
        return 1.0 / self.timing_profiles.get(profile, 100)

    def get_pcap_path(self) -> Optional[Path]:
        """Get PCAP directory path if PCAP saving is enabled."""
        return self.pcap_dir if self.save_pcap else None
