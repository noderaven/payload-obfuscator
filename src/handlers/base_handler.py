"""
Base Handler Module
=================

This module provides the base handler class with common utilities and error handling
for all specialized handlers in the payload obfuscator project.
"""

from typing import Dict, Any
from loguru import logger

class HandlerError(Exception):
    """Base exception for all handler errors."""
    def __init__(self, message: str, details: Dict[str, Any] = None):
        self.details = details or {}
        super().__init__(message)

class BaseHandler:
    """Base class for all handlers in the payload obfuscator project."""
    
    def __init__(self):
        """Initialize the base handler."""
        self.logger = logger
    
    def _log_error(self, message: str, error: Exception = None, details: Dict[str, Any] = None):
        """
        Log an error with optional exception details.
        
        Args:
            message: Main error message
            error: Optional exception object
            details: Optional dictionary of additional details
        """
        error_msg = f"[red]{message}[/red]"
        if error:
            error_msg += f"\n  Error: {str(error)}"
        if details:
            error_msg += "\n  Details:"
            for key, value in details.items():
                error_msg += f"\n    {key}: {value}"
        self.logger.error(error_msg)
    
    def _log_warning(self, message: str, details: Dict[str, Any] = None):
        """
        Log a warning message with optional details.
        
        Args:
            message: Warning message
            details: Optional dictionary of additional details
        """
        warning_msg = f"[yellow]{message}[/yellow]"
        if details:
            warning_msg += "\n  Details:"
            for key, value in details.items():
                warning_msg += f"\n    {key}: {value}"
        self.logger.warning(warning_msg)
    
    def _log_success(self, message: str, details: Dict[str, Any] = None):
        """
        Log a success message with optional details.
        
        Args:
            message: Success message
            details: Optional dictionary of additional details
        """
        success_msg = f"[green]{message}[/green]"
        if details:
            success_msg += "\n  Details:"
            for key, value in details.items():
                success_msg += f"\n    {key}: {value}"
        self.logger.success(success_msg)
    
    def _format_hex(self, value: int) -> str:
        """
        Format an integer as a hexadecimal string.
        
        Args:
            value: Integer to format
            
        Returns:
            str: Formatted hexadecimal string
        """
        return f"0x{value:X}"
    
    def _format_size(self, size: int) -> str:
        """
        Format a size in bytes with appropriate units.
        
        Args:
            size: Size in bytes
            
        Returns:
            str: Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB" 