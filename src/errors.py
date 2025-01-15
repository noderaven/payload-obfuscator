"""
Base error classes for the payload obfuscator.

This module defines the base error classes used throughout the project
for consistent error handling.
"""

class HandlerError(Exception):
    """Base class for all handler errors."""
    
    def __init__(self, message: str, details: dict = None, cause: Exception = None, remediation: str = None):
        """
        Initialize handler error.
        
        Args:
            message: Error message
            details: Additional error details
            cause: Original exception that caused this error
            remediation: Suggested fix for the error
        """
        self.message = message
        self.details = details or {}
        self.cause = cause
        self.remediation = remediation
        
        # Build error message
        msg_parts = [message]
        if details:
            msg_parts.append(f"Details: {details}")
        if cause:
            msg_parts.append(f"Caused by: {str(cause)}")
        if remediation:
            msg_parts.append(f"Remediation: {remediation}")
            
        super().__init__("\n".join(msg_parts))
        
class ValidationError(HandlerError):
    """Raised when validation fails."""
    pass
    
class ConfigurationError(HandlerError):
    """Raised when configuration is invalid."""
    pass
    
class OperationError(HandlerError):
    """Raised when an operation fails."""
    pass 