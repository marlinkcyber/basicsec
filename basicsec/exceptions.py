"""
Custom exceptions for the basicsec library
"""


class SecurityScanError(Exception):
    """Base exception for security scanning errors"""
    pass


class DomainNotFoundError(SecurityScanError):
    """Raised when a domain cannot be resolved"""
    pass


class DNSTimeoutError(SecurityScanError):
    """Raised when DNS queries timeout"""
    pass


class SMTPConnectionError(SecurityScanError):
    """Raised when SMTP connection fails"""
    pass