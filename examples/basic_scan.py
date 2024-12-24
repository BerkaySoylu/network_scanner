# examples/basic_scan.py
#!/usr/bin/env python3
from network_scanner import NetworkScanner, ScannerSettings
import asyncio
from rich.console import Console

async def main():
    # Initialize console for rich output
    console = Console()
    
    try:
        # Create scanner with default settings
        settings = ScannerSettings(
            default_timeout=2.0,
            default_ports=[80, 443, 22, 21]  # Common ports
        )
        
        scanner = NetworkScanner(settings, verbose=True)
        
        # Perform scan
        console.print("[cyan]Starting basic scan of example.com...[/cyan]")
        results = await scanner.scan("example.com")
        
        # Print results
        console.print("\n[green]Scan Results:[/green]")
        console.print(f"Target: {results.target}")
        console.print(f"Status: {results.status}")
        
        if results.os_info:
            console.print(f"OS Detection: {results.os_info}")
        
        console.print("\n[yellow]Open Ports:[/yellow]")
        for port in results.ports:
            if port['state'] == 'open':
                console.print(
                    f"Port {port['port']}: {port['service']} "
                    f"({port.get('version', 'unknown version')})"
                )

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
