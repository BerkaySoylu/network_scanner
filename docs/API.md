# API Documentation

## Core Classes

### NetworkScanner

The main scanner class that coordinates all scanning operations.

python
from network_scanner import NetworkScanner, ScannerSettings
scanner = NetworkScanner(
settings=ScannerSettings(),
verbose=True
)
results = await scanner.scan("example.com")

#### Methods

- `scan(target: str, ports: Optional[List[int]] = None, scan_types: Optional[List[str]] = None) -> ScanResult`
- `initialize() -> bool`
- `stop() -> None`

### ScannerSettings

Configuration class for scanner settings.

python
settings = ScannerSettings(
default_timeout=2.0,
default_ports=[80, 443, 22],
timing_profiles={
"slow": 0.5,
"normal": 1.0,
"fast": 10.0
}
)

## Scanner Types

### TCPConnectScanner

Performs TCP connect scans.

python
scanner = TCPConnectScanner(target, source_ip, interface)
result = await scanner.scan_port(80)


### SYNScanner

Performs SYN (stealth) scans.

python
scanner = SYNScanner(target, source_ip, interface)
result = await scanner.scan_port(443)

### UDPScanner

Performs UDP scans.

python
scanner = UDPScanner(target, source_ip, interface)
result = await scanner.scan_port(53)

## Utility Classes

### OutputFormatter

Handles result output in various formats.

python
from network_scanner.utils.helpers import OutputFormatter
OutputFormatter.to_json(results, "scan_results.json")
OutputFormatter.to_csv(results, "scan_results.csv")

### ProgressTracker

Tracks and displays scan progress.

python
with ProgressTracker() as progress:
progress.add_task("Scanning", total=100)
# Perform scan

## Error Handling

The scanner uses custom exceptions for different error cases:
python
from network_scanner.utils.exceptions import (
ScannerError,
NetworkError,
PermissionError
)
try:
results = await scanner.scan(target)
except PermissionError:
print("Insufficient permissions")
except NetworkError:
print("Network error occurred")
except ScannerError as e:
print(f"Scanner error: {e}")


