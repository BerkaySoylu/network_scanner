# examples/advanced_scan.py
#!/usr/bin/env python3
from network_scanner import NetworkScanner, ScannerSettings
from network_scanner.utils.helpers import ProgressTracker
import asyncio
import argparse
from rich.console import Console
from pathlib import Path

async def main():
    console = Console()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Advanced Network Scanner Example")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--ports", help="Port range (e.g., 80,443 or 1-1000)")
    parser.add_argument("--timing", choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                      default="normal", help="Scan timing profile")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    try:
        # Configure scanner settings
        settings = ScannerSettings(
            default_timeout=2.0 if args.timing == "normal" else 5.0,
            output_dir=Path("results"),
            save_pcap=True,
            pcap_dir=Path("pcaps")
        )

        # Initialize scanner
        scanner = NetworkScanner(settings, verbose=True)
        
        # Parse ports
        if args.ports:
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p) for p in args.ports.split(",")]
        else:
            ports = settings.default_ports

        # Create progress tracker
        with ProgressTracker() as progress:
            progress.add_task("Scanning", total=len(ports))
            
            # Perform scan
            results = await scanner.scan(
                args.target,
                ports=ports,
                scan_types=["syn", "udp"]  # Use both SYN and UDP scans
            )

        # Print detailed results
        console.print("\n[green]Scan Complete![/green]")
        console.print(f"\nTarget: {results.target}")
        console.print(f"Status: {results.status}")
        
        if results.os_info:
            console.print(f"Operating System: {results.os_info}")
            console.print(f"TTL: {results.ttl}")

        # Print port results by state
        for state in ["open", "filtered", "closed"]:
            ports = [p for p in results.ports if p['state'] == state]
            if ports:
                console.print(f"\n[yellow]{state.upper()} PORTS:[/yellow]")
                for port in ports:
                    service_info = f"{port['service']}"
                    if port.get('version'):
                        service_info += f" ({port['version']})"
                    console.print(
                        f"Port {port['port']}: {service_info}"
                    )

        # Print statistics
        console.print("\n[cyan]Scan Statistics:[/cyan]")
        for key, value in results.statistics.items():
            console.print(f"{key.replace('_', ' ').title()}: {value}")

        # Save results if output specified
        if args.output:
            from network_scanner.utils.helpers import OutputFormatter
            OutputFormatter.to_json(results.__dict__, args.output)
            console.print(f"\nResults saved to: {args.output}")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
