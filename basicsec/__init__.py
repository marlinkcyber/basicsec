"""
Basic Security Scanner Library

A Python library for passive DNS and email security scanning.
Provides tools to check domain configurations for common security issues.
"""

from .scanner import BasicSecurityScanner
from .exceptions import DomainNotFoundError, SecurityScanError

__version__ = "1.0.1"
__author__ = "Vlatko Kosturjak"
__email__ = "vlatko.kosturjak@marlink.com"

__all__ = ["BasicSecurityScanner", "DomainNotFoundError", "SecurityScanError"]
