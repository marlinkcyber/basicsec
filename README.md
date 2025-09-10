# BasicSec

A Python library and CLI tool for basic and mostly passive security scanning like DNS and e-mail.

## Features

- **DNS Security Checks**: MX records, SPF, DMARC, DNSSEC validation
- **Passive Scanning**: DNS-only checks that don't connect to target servers
- **Active Scanning**: Includes SMTP connection testing and STARTTLS validation
- **Batch Processing**: Scan multiple domains efficiently
- **CLI Tool**: Easy-to-use command line interface
- **Library API**: Integrate security checks into your Python applications

## Installation

```bash
pip install basicsec
```

## Quick Start

### Command Line Usage

```bash
# Passive scan of a single domain
basicsec example.com

# Active scan with SMTP tests
basicsec example.com --active

# Scan multiple domains
basicsec example.com google.com --multiple

# Quick checks only
basicsec example.com --quick --checks live mx spf

# JSON output
basicsec example.com --json
```

### Python Library Usage

```python
from basicsec import BasicSecurityScanner

# Initialize scanner
scanner = EmailSecurityScanner()

# Passive scan
result = scanner.passive_scan("example.com")
print(f"SPF Valid: {result['spf_valid']}")
print(f"DMARC Valid: {result['dmarc_valid']}")
print(f"DNSSEC Enabled: {result['dnssec_enabled']}")

# Active scan (includes SMTP tests)
result = scanner.active_scan("example.com")
print(f"SMTP Connection: {result['has_smtp_connection']}")
print(f"STARTTLS Support: {result['supports_starttls']}")

# Quick batch check
result = scanner.quick_domain_check(
    ["example.com", "google.com"],
    check_types=["live", "mx", "spf", "dmarc"]
)
```

## Security Checks

### DNS Records
- **MX Records**: Mail exchange server configuration
- **SPF Records**: Sender Policy Framework validation
- **DMARC Records**: Domain-based Message Authentication validation
- **DNSSEC**: DNS Security Extensions status and validation

### SMTP Tests (Active Mode)
- **Connection Testing**: Verify SMTP server connectivity
- **STARTTLS Support**: Check for encrypted connection capability
- **Multiple Ports**: Test common SMTP ports (25, 465, 587)

## CLI Options

```
usage: basicsec [-h] [--active | --passive | --quick] [--multiple]
                [--checks {live,mx,spf,dmarc,dnssec} [{live,mx,spf,dmarc,dnssec} ...]]
                [--json] [--timeout TIMEOUT] [--verbose]
                domains [domains ...]

positional arguments:
  domains               Domain(s) to scan

optional arguments:
  --active              Perform active scan (includes SMTP tests)
  --passive             Perform passive scan (DNS only, default)
  --quick               Quick check mode (fastest)
  --multiple            Scan multiple domains
  --checks              Types of quick checks to perform
  --json                Output results in JSON format
  --timeout TIMEOUT     DNS timeout in seconds (default: 5.0)
  --verbose, -v         Enable verbose logging
```

## Exit Codes

The CLI returns exit codes based on security issues found:
- `0`: No issues detected
- `1-3`: Number of security issues found (SPF, DMARC, DNSSEC)

## Requirements

- Python 3.8+
- dnspython>=2.3.0
- email-validator>=2.0.0

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 basicsec/
black basicsec/

# Type checking
mypy basicsec/
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Security Considerations

This tool is designed for **defensive security analysis only**. It performs:

- Passive DNS lookups
- Standard protocol connections (SMTP)
- Public record validation

It does **not** perform:
- Vulnerability exploitation
- Unauthorized access attempts
- Aggressive scanning techniques

Always ensure you have permission to scan the target domains.
