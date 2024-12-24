#!/usr/bin/env python3
import asyncio
import argparse
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime

from network_scanner import NetworkScanner, ScannerSettings
from network_scanner.utils.validators import InputValidator
from network_scanner.utils.logging import LogManager
from network_scanner.config.constants import PORT_SERVICES

console = Console()
log_manager = LogManager()

class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self) -> None:
        """Override the print_help method to use Rich console"""
        help_text = """
[bold cyan]
╔═══════════════════════════════════════════╗
║             Network Scanner               ║
║         Advanced Security Tool            ║
╚═══════════════════════════════════════════╝[/bold cyan]

[bold cyan]🚀 USAGE:[/bold cyan]
    python main.py [OPTIONS] TARGET

[bold cyan]🎛️  OPTIONS:[/bold cyan]
    [green]TARGET[/green]
        🎯 Target IP address or hostname

    [green]-p, --ports[/green] [yellow]<port-range>[/yellow]
        🔍 Port(s) to scan (e.g., 80,443 or 20-25)
        Default: 1-1024

    [green]-t, --type[/green] [yellow]<scan-type>[/yellow]
        🔧 Scan type (tcp/syn/udp)
        Default: tcp

    [green]--timing[/green] [yellow]<timing-template>[/yellow]
        ⚡ Timing template
        Options: paranoid/sneaky/polite/normal/aggressive/insane
        Default: normal

    [green]-o, --output[/green] [yellow]<file>[/yellow]
        💾 Output file path
        Default: stdout

    [green]--format[/green] [yellow]<format>[/yellow]
        📊 Output format (text/json/csv)
        Default: text

    [green]--pcap[/green] [yellow]<directory>[/yellow]
        📦 Enable PCAP capture and specify directory
        Default: disabled

    [green]-v, --verbose[/green]
        🔊 Enable verbose output

    [green]--debug[/green]
        🐛 Enable debug mode

[bold cyan]📚 EXAMPLES:[/bold cyan]
    Basic TCP scan:
    [green]python main.py 192.168.1.1[/green]

    SYN scan specific ports:
    [green]python main.py 192.168.1.1 -p 80,443 -t syn[/green]

    Full scan with PCAP capture:
    [green]python main.py 192.168.1.1 -p 1-65535 --pcap ./captures/[/green]

    Aggressive scan with JSON output:
    [green]python main.py 192.168.1.1 --timing aggressive -o results.json --format json[/green]

[bold cyan]🛡️  SECURITY NOTE:[/bold cyan]
    [yellow]Please ensure you have permission to scan the target network/host.[/yellow]
"""
        console.print(help_text)
        
    def format_help(self) -> str:
        return ""  # Return empty string as we're handling the printing directly

def parse_arguments() -> argparse.Namespace:
    parser = CustomArgumentParser(
        description="Advanced Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )

    # Add help option
    parser.add_argument(
        '-h', '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='Show this help message'
    )

    # Target specification
    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    # Port specification
    parser.add_argument(
        "-p", "--ports",
        help="Port(s) to scan (e.g., 80,443 or 20-25)",
        default="1-1024"
    )

    # Scan type
    parser.add_argument(
        "-t", "--type",
        choices=["tcp", "syn", "udp"],
        default="tcp",
        help="Scan type (default: tcp)"
    )

    # Timing and performance
    parser.add_argument(
        "--timing",
        choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
        default="normal",
        help="Timing template (default: normal)"
    )

    # Output options
    parser.add_argument(
        "-o", "--output",
        help="Output file path",
        type=Path
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)"
    )

    # PCAP capture
    parser.add_argument(
        "--pcap",
        help="Enable PCAP capture and specify save directory",
        type=Path
    )

    # Verbosity
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )

    return parser.parse_args()

def validate_input(args: argparse.Namespace) -> tuple[str, List[int]]:
    # Validate target
    target_result = InputValidator.validate_ip_or_hostname(args.target)
    if not target_result.is_valid:
        console.print(f"[red]Error:[/red] {target_result.message}")
        exit(1)

    # Validate ports
    ports_result = InputValidator.validate_ports(args.ports)
    if not ports_result.is_valid:
        console.print(f"[red]Error:[/red] {ports_result.message}")
        exit(1)

    return target_result.value, ports_result.value

def create_output_table(scan_result: dict) -> Table:
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version", overflow="fold")
    table.add_column("Reason")

    for port_info in scan_result["ports"]:
        state_color = {
            "open": "green",
            "closed": "red",
            "filtered": "yellow"
        }.get(port_info["state"], "white")

        table.add_row(
            str(port_info["port"]),
            f"[{state_color}]{port_info['state']}[/{state_color}]",
            port_info.get("service", "unknown"),
            port_info.get("version", ""),
            port_info.get("reason", "")
        )

    return table

async def main():
    args = parse_arguments()

    # Setup logging
    log_level = "DEBUG" if args.debug else ("INFO" if args.verbose else "WARNING")
    log_manager.setup_logging(level=log_level, dev_mode=args.debug)

    # Validate input
    target, ports = validate_input(args)

    # Create scanner settings
    settings = ScannerSettings(
        save_pcap=bool(args.pcap),
        pcap_dir=args.pcap,
        dev_mode=args.debug
    )

    # Initialize scanner
    scanner = NetworkScanner(
        settings=settings,
        verbose=args.verbose,
        dev_mode=args.debug
    )

    try:
        console.print(f"\n[cyan]Starting scan of {target}[/cyan]")
        console.print(f"Scan type: [yellow]{args.type.upper()}[/yellow]")
        console.print(f"Ports: [yellow]{args.ports}[/yellow]\n")

        # Perform scan
        start_time = datetime.now()
        results = await scanner.scan(target, ports=ports, scan_types=[args.type])
        duration = (datetime.now() - start_time).total_seconds()

        # Display results
        if results.status == "up":
            console.print(f"\n[green]Host is up[/green]")
            if results.os_info:
                console.print(f"OS Detection: [blue]{results.os_info}[/blue]")
            
            # Print statistics
            stats = results.statistics
            console.print(f"\nPorts: [green]{stats['open']} open[/green], "
                         f"[red]{stats['closed']} closed[/red], "
                         f"[yellow]{stats['filtered']} filtered[/yellow]")
            
            # Display results table
            table = create_output_table(results.__dict__)
            console.print(table)
            
            console.print(f"\nScan completed in [cyan]{duration:.2f}[/cyan] seconds")

            # Save results if output file specified
            if args.output:
                from network_scanner.utils.helpers import OutputFormatter
                if args.format == "json":
                    OutputFormatter.to_json(results.__dict__, args.output)
                elif args.format == "csv":
                    OutputFormatter.to_csv(results.__dict__, args.output)
                console.print(f"\nResults saved to: [cyan]{args.output}[/cyan]")
        else:
            console.print(f"\n[red]Host appears to be down[/red]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        if args.debug:
            import traceback
            console.print(traceback.format_exc())
    finally:
        await scanner.stop()

if __name__ == "__main__":
    asyncio.run(main()) 