Installation Guide
Prerequisites
- Python 3.9 or higher
- pip (Python package installer)
- Root/Administrator privileges for scanning
- libpcap development files (for packet capture)

Basic Installation
# Install using pip
pip install network-scanner

# Or install from source
git clone https://github.com/berkaysoylu/network-scanner.git
cd network-scanner
pip install -e .

System-Specific Instructions

Linux
# Install required system packages
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev

# Install the scanner
pip install network-scanner


macOS
# Install using Homebrew
brew install libpcap

# Install the scanner
pip install network-scanner

Development Installation
# Clone the repository
git clone https://github.com/berkaysoylu/network-scanner.git
cd network-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

Verifying Installation
# Check if the scanner is installed correctly
python -m network_scanner --version

# Run a test scan (requires root/admin privileges)
sudo python -m network_scanner scan localhost
