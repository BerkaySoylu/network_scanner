# examples/custom_scan.py
#!/usr/bin/env python3
from network_scanner import NetworkScanner, ScannerSettings
from network_scanner.scanners import BaseScanner, PortResult
import asyncio
from rich.console import Console
from typing import Optional

# Custom scanner implementation
class CustomScanner(BaseScanner):
    async def scan_port(self, port: int) -> PortResult:
        # Implement custom scanning logic
        # This is just an example
        return PortResult(
            port=port,
            state="open",
            service="custom",
            version="1.0"
        )

    async def cleanup(self) -> None:
        pass

async def main():
    console = Console()
    
    # Custom settings
    settings = ScannerSettings(
        default_timeout=3.0,
        default_ports=[80, 443, 8080]
    )
    
    # Initialize scanner with custom settings
    scanner = NetworkScanner(settings, verbose=True)
    
    # Register custom scanner
    scanner.scanner_types["custom"] = CustomScanner
    
    try:
        # Perform scan with custom scanner
        results = await scanner.scan(
            "example.com",
            scan_types=["custom"]
        )
        
        # Print results
        console.print("\n[green]Custom Scan Results:[/green]")
        console.print(f"Target: {results.target}")
        console.print(f"Status: {results.status}")
        
        for port in results.ports:
            console.print(
                f"Port {port['port']}: {port['state']} "
                f"({port['service']} {port.get('version', '')})"
            )
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
