# Network Scanner

A powerful and flexible network scanning tool built in Python, supporting multiple scanning techniques and protocols.

## Features

- Multiple scanning techniques:
  - TCP Connect Scan
  - SYN Scan (stealth)
  - UDP Scan
- Host discovery
- OS fingerprinting
- Service version detection
- PCAP capture support
- Rate limiting and timing controls
- Concurrent scanning
- Rich console output
- JSON/CSV export

## Installation

### Prerequisites

- Python 3.8 or higher
- libpcap development files (for packet capture)

On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev
```

On RHEL/CentOS:
```bash
sudo yum install python3-devel libpcap-devel
```

### Installing the Package

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network_scanner.git
cd network_scanner
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
.\venv\Scripts\activate  # On Windows
```

3. Install with Poetry:
```bash
pip install poetry
poetry install
```

## Usage

### Basic Scanning

```bash
# Basic TCP scan
poetry run python src/main.py example.com -p 80,443

# Scan multiple ports
poetry run python src/main.py 192.168.1.1 -p 22,80,443,3306

# Scan a CIDR range
poetry run python src/main.py 192.168.1.0/24 -p 80

# Enable verbose output
poetry run python src/main.py example.com -p 80,443 -v
```

### Advanced Scanning

```bash
# SYN scan (requires root/sudo)
sudo poetry run python src/main.py example.com -s syn -p 80,443

# UDP scan
poetry run python src/main.py example.com -s udp -p 53,161

# Aggressive timing
poetry run python src/main.py example.com --timing aggressive -p 1-1000

# Save results
poetry run python src/main.py example.com -p 80,443 -o results.json

# Enable packet capture
poetry run python src/main.py example.com -p 80,443 --pcap ./captures
```

### Timing Templates

- `paranoid`: Very slow (0.5 packets/sec)
- `sneaky`: Slow (1 packet/sec)
- `polite`: Normal (10 packets/sec)
- `normal`: Default (100 packets/sec)
- `aggressive`: Fast (500 packets/sec)
- `insane`: Very fast (1000 packets/sec)

## Configuration

The scanner can be configured through command-line arguments or environment variables:

```bash
# Environment variables
export SCANNER_DEFAULT_TIMEOUT=2.0
export SCANNER_MAX_CONCURRENT_SCANS=100

# Command line options
poetry run python src/main.py example.com \
    -p 80,443 \
    --timing normal \
    --output results.json \
    --pcap ./captures \
    --debug
```

## Security Considerations

- Always obtain permission before scanning networks
- Some scan types (SYN, UDP) require root/administrator privileges
- Be aware of local laws and regulations regarding port scanning
- Use appropriate timing templates to avoid detection/blocking

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Scapy library for packet manipulation
- Rich library for console output
- Poetry for dependency management