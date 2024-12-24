# src/network_scanner/utils/helpers.py
from typing import Dict, Any, List, Optional
import json
import csv
from pathlib import Path
import time
from rich.progress import Progress, TaskID
from rich.console import Console
from datetime import datetime

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class OutputFormatter:
    @staticmethod
    def to_json(data: Dict[str, Any], file_path: str) -> None:
        """Save scan results to JSON file."""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4, cls=DateTimeEncoder)

    @staticmethod
    def to_csv(data: Dict[str, Any], file_path: str) -> None:
        """Save scan results to CSV file."""
        if not data.get('ports'):
            return

        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'State', 'Service', 'Version', 'Reason'])
            for port in data['ports']:
                writer.writerow([
                    port.get('port', ''),
                    port.get('state', ''),
                    port.get('service', ''),
                    port.get('version', ''),
                    port.get('reason', '')
                ])

class ProgressTracker:
    def __init__(self):
        self.console = Console()
        self.progress = Progress()
        self.tasks: Dict[str, TaskID] = {}

    def __enter__(self):
        self.progress.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.stop()

    def add_task(self, name: str, total: int) -> None:
        """Add a new task to track."""
        self.tasks[name] = self.progress.add_task(
            f"[cyan]{name}...",
            total=total
        )

    def update_task(self, name: str, advance: int = 1) -> None:
        """Update task progress."""
        if name in self.tasks:
            self.progress.update(self.tasks[name], advance=advance)

class RateLimiter:
    def __init__(self, rate: float):
        """Initialize rate limiter with packets per second."""
        self.rate = rate
        self.last_check = time.time()
        self.allowance = rate

    async def acquire(self) -> None:
        """Wait if necessary to maintain rate limit."""
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.allowance += time_passed * self.rate

        if self.allowance > self.rate:
            self.allowance = self.rate

        if self.allowance < 1:
            await time.sleep((1 - self.allowance) / self.rate)
            self.allowance = 0
        else:
            self.allowance -= 1
