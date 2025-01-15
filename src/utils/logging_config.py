"""
Logging configuration for the payload obfuscator.

This module provides a centralized configuration for logging using loguru and rich.
It ensures consistent formatting and proper log level handling across the application.
"""

import os
import sys
from pathlib import Path
from typing import Optional
from loguru import logger
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Define log levels and their rich formatting
LOG_LEVELS = {
    "TRACE": {"color": "dim blue", "icon": "🔍"},
    "DEBUG": {"color": "blue", "icon": "🐛"},
    "INFO": {"color": "cyan", "icon": "ℹ️"},
    "SUCCESS": {"color": "green", "icon": "✅"},
    "WARNING": {"color": "yellow", "icon": "⚠️"},
    "ERROR": {"color": "red", "icon": "❌"},
    "CRITICAL": {"color": "bold red", "icon": "💀"}
}

def setup_logging(console: Console, log_dir: str, context: Optional[dict] = None) -> None:
    """
    Configure logging with both console and file handlers.
    
    Args:
        console: Rich console instance for output
        log_dir: Directory for log files
        context: Optional dictionary of context variables for logging
    """
    try:
        # Remove any existing handlers
        logger.remove()
        
        # Ensure log directory exists
        log_dir = Path(log_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure console logging with rich
        console_format = (
            "<level>{level.icon}</level> "
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
        
        # Add rich handler for console output
        logger.add(
            RichHandler(
                console=console,
                show_path=False,
                enable_link_path=True,
                markup=True,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
                tracebacks_theme="monokai",
                log_time_format="[%X]",
                omit_repeated_times=False,
                show_level=True
            ),
            format=console_format,
            level="INFO",
            enqueue=True,
            backtrace=True,
            diagnose=True,
            catch=True
        )
        
        # Configure detailed file logging
        file_format = (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
            "{level: <8} | "
            "process:{process}:{thread} | "
            "{name}:{function}:{line} | "
            "{message}"
        )
        
        # Add rotating file handler
        log_file = log_dir / "obfuscator.log"
        logger.add(
            str(log_file),
            format=file_format,
            level="DEBUG",
            rotation="100 MB",
            retention="1 week",
            compression="zip",
            enqueue=True,
            backtrace=True,
            diagnose=True,
            catch=True,
            serialize=True  # JSON format for better parsing
        )
        
        # Add error-specific log file
        error_log = log_dir / "errors.log"
        logger.add(
            str(error_log),
            format=file_format,
            level="ERROR",
            rotation="100 MB",
            retention="1 month",
            compression="zip",
            enqueue=True,
            backtrace=True,
            diagnose=True,
            catch=True,
            serialize=True
        )
        
        # Configure log levels with custom formatting
        for level, settings in LOG_LEVELS.items():
            logger.level(level, color=f"<{settings['color']}>")
            setattr(logger.level(level), "icon", settings["icon"])
        
        # Add context if provided
        if context:
            logger.configure(extra=context)
        
        # Log initial messages
        logger.info("Logging system initialized")
        logger.debug(f"Log directory: {log_dir}")
        if context:
            logger.debug(f"Logging context: {context}")
        
    except Exception as e:
        print(f"Error setting up logging: {str(e)}", file=sys.stderr)
        sys.exit(1)


def get_logger():
    """Get configured logger instance."""
    return logger 