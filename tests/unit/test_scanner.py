import pytest
from network_scanner import NetworkScanner, ScannerSettings

@pytest.mark.asyncio
async def test_scanner_initialization():
    settings = ScannerSettings(default_timeout=1.0)
    scanner = NetworkScanner(settings)
    assert scanner.settings.default_timeout == 1.0

@pytest.mark.asyncio
async def test_basic_scan():
    scanner = NetworkScanner()
    results = await scanner.scan("example.com", ports=[80])
    assert "results" in results
    assert isinstance(results["results"], list)
