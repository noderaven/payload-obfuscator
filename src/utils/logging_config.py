"""
Logging configuration for the payload obfuscator.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any
from loguru import logger
from rich.console import Console

def setup_logging(console: Console, output_dir: str, context: Dict[str, Any]) -> None:
    """
    Configure logging with file and console outputs.
    
    Args:
        console: Rich console instance for formatted output
        output_dir: Directory for log files
        context: Additional context for log records
    """
    try:
        # Create logs directory
        log_dir = Path(output_dir) / "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        # Log file path
        log_file = log_dir / f"obfuscator_{context.get('session_id', 'unknown')}.log"
        
        # Remove default handler
        logger.remove()
        
        # Add file handler with plain formatting
        logger.add(
            str(log_file),
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
            rotation="1 day",
            retention="1 week",
            compression="zip"
        )
        
        # Add console handler with rich formatting
        def console_formatter(record):
            level_colors = {
                "DEBUG": "blue",
                "INFO": "cyan",
                "SUCCESS": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold red"
            }
            color = level_colors.get(record["level"].name, "white")
            return f"[{color}]{record['message']}[/{color}]"
            
        logger.add(
            lambda msg: console.print(msg),
            level="INFO",
            format=console_formatter
        )
        
        # Add context to all future logs
        logger.configure(extra=context)
        
        logger.debug("Logging configured successfully", context=context)
        
    except Exception as e:
        print(f"Failed to setup logging: {str(e)}", file=sys.stderr)
        raise


def get_logger():
    """Get configured logger instance."""
    return logger 