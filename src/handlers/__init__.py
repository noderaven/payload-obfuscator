"""
Handlers Package
==============

This package provides handlers for various file operations:
- PEHandler: Main handler for PE file operations
- BaseHandler: Base class for all handlers
"""

from .base_handler import BaseHandler, HandlerError
from .pe_handler import PEHandler, PEHandlerError

__all__ = [
    'BaseHandler',
    'HandlerError',
    'PEHandler',
    'PEHandlerError'
] 