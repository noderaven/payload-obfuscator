"""
Base handler functionality.

This module provides base classes for all handlers in the project.
"""

from typing import Dict, Optional, Any
from loguru import logger

class HandlerError(Exception):
    """Base exception for handler operations."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        remediation: Optional[str] = None
    ):
        """
        Initialize handler error.
        
        Args:
            message: Error message
            details: Optional error details
            cause: Optional causing exception
            remediation: Optional remediation steps
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause
        self.remediation = remediation

class BaseHandler:
    """Base class for all handlers."""
    
    def __init__(self):
        """Initialize base handler."""
        self.logger = logger.bind(handler=self.__class__.__name__.lower())
        
    def _log_success(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Log success message with optional details."""
        self.logger.success(message, details=details)
        
    def _log_error(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Log error message with optional details."""
        self.logger.error(message, details=details) 