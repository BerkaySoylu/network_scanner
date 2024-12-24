# examples/async_batch_scan.py
#!/usr/bin/env python3
from network_scanner import NetworkScanner, ScannerSettings
import asyncio
from rich.console import Console
from rich.progress import Progress
import ipaddress
from typing import List

async def scan_target(scanner: NetworkScanner, target: str, progress) -> dict:
    """Scan a single target and update progress."""
    try:
        results = await scanner.scan(target)
        progress.advance(task_id)
        return {target: results}
    except Exception as e:
        return {target: f"Error: {str(e)}"}

async def main():
    console = Console()
    
    # Configure scanner
    settings = ScannerSettings(
        default_timeout=2.0,
        max_concurrent_scans=50  # Limit concurrent scans
    )
    
    scanner = NetworkScanner(settings)
    
    # Define target network
    network = "192.168.1.0/24"  # Example network range
    targets = [str(ip) for ip in ipaddress.IPv4Network(network)]
    
    console.print(f"[cyan]Starting batch scan of {network}...[/cyan]")
    
    # Create progress bar
    with Progress() as progress:
        task_id = progress.add_task("[cyan]Scanning...", total=len(targets))
        
        # Create tasks for each target
        tasks = []
        for target in targets:
            task = scan_target(scanner, target, progress)
            tasks.append(task)
        
        # Run scans with concurrency limit
        results = []
        for batch in range(0, len(tasks), settings.max_concurrent_scans):
            batch_tasks = tasks[batch:batch + settings.max_concurrent_scans]
            batch_results = await asyncio.gather(*batch_tasks)
            results.extend(batch_results)
    
    # Print summary
    console.print("\n[green]Scan Complete![/green]")
    
    # Process results
    active_hosts = 0
    for result in results:
        for target, scan_result in result.items():
            if isinstance(scan_result, dict) and scan_result.get('status') == 'up':
                active_hosts += 1
                console.print(f"\n[yellow]Host: {target}[/yellow]")
                open_ports = [p for p in scan_result['ports'] if p['state'] == 'open']
                if open_ports:
                    for port in open_ports:
                        console.print(
                            f"  Port {port['port']}: {port['service']}"
                        )
    
    console.print(f"\nFound {active_hosts} active hosts")

if __name__ == "__main__":
    asyncio.run(main())
