Usage Guide
Basic Usage
Simple Scan

from network_scanner import NetworkScanner
import asyncio

async def main():
    scanner = NetworkScanner()
    results = await scanner.scan("example.com")
    print(results)

asyncio.run(main())

Scanning Specific Ports
results = await scanner.scan(
    "example.com",
    ports=[80, 443, 8080]
)

Using Different Scan Types
results = await scanner.scan(
    "example.com",
    scan_types=["tcp", "syn", "udp"]
)

Advanced Usage
Custom Timing Profiles
from network_scanner import ScannerSettings

settings = ScannerSettings(
    timing_profiles={
        "stealthy": 0.1,  # 1 packet every 10 seconds
        "normal": 1.0,    # 1 packet per second
        "aggressive": 10  # 10 packets per second
    }
)
scanner = NetworkScanner(settings)

With PCAP Capture
settings = ScannerSettings(save_pcap=True)
scanner = NetworkScanner(settings)
results = await scanner.scan("example.com")

Batch Scanning
async def scan_multiple(targets):
    scanner = NetworkScanner()
    tasks = [scanner.scan(target) for target in targets]
    return await asyncio.gather(*tasks)

targets = ["example.com", "example.org"]
results = await scan_multiple(targets)

Command Line Usage
Basic Scan
sudo python3 -m network_scanner scan example.com

Advanced Options
sudo python3 -m network_scanner scan example.com \
    --ports 80,443,8080 \
    --timing fast \
    --output results.json \
    --pcap
    
Output Formats
JSON Output
from network_scanner.utils.helpers import OutputFormatter

OutputFormatter.to_json(results, "scan_results.json")

CSV Output
OutputFormatter.to_csv(results, "scan_results.csv")
