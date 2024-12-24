# src/network_scanner/utils/logging.py
import logging
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme
import sys

class LogManager:
    def __init__(self):
        self.console = Console(theme=Theme({
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
            "debug": "grey70"
        }))

    def setup_logging(
        self,
        level: str = "INFO",
        log_file: Optional[str] = None,
        dev_mode: bool = False
    ) -> None:
        """Configure logging with rich output and optional file logging."""
        # Set up rich handler
        rich_handler = RichHandler(
            console=self.console,
            show_time=True,
            show_path=dev_mode,
            markup=True
        )

        # Configure logging format
        log_format = "%(message)s"
        if dev_mode:
            log_format = "%(name)s: %(message)s"

        # Set up basic configuration
        handlers = [rich_handler]
        
        # Add file handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
            handlers.append(file_handler)

        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            format=log_format,
            handlers=handlers
        )

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance with the specified name."""
        return logging.getLogger(name)

    def log_error_and_exit(self, message: str, exit_code: int = 1) -> None:
        """Log error message and exit the program."""
        self.console.print(f"[red]Error:[/red] {message}")
        sys.exit(exit_code)
