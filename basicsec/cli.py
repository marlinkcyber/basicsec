"""
Command line interface for basicsec
"""

import argparse
import json
import logging
import sys
from typing import List, Optional

from .scanner import BasicSecurityScanner

logger = logging.getLogger(__name__)


def read_domains_from_file(file_path: str) -> List[str]:
    """Read domains from file, one domain per line"""
    domains = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # Strip whitespace and skip empty lines and comments
                domain = line.strip()
                if not domain or domain.startswith('#'):
                    continue
                
                # Basic domain validation - check for valid characters
                if domain.replace('-', '').replace('.', '').replace('_', '').isalnum():
                    domains.append(domain.lower())
                else:
                    logger.warning(f"Skipping invalid domain on line {line_num}: {domain}")
        
        logger.info(f"Read {len(domains)} domains from {file_path}")
        return domains
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading file '{file_path}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)


def setup_logging(verbose: bool):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def print_results(results, output_format: str = "text"):
    """Print scan results in specified format"""
    if output_format.lower() == "json":
        print(json.dumps(results, indent=2, default=str))
        return
    
    if isinstance(results, dict) and 'results' in results:
        # Multiple domain results
        print(f"\nScanned {results['total_domains']} domains:")
        print(f"Successful: {results.get('successful_scans', results.get('successful_checks', 0))}, Failed: {results.get('failed_scans', results.get('failed_checks', 0))}")
        print(f"Scan type: {results['scan_type']}")
        print("-" * 60)
        
        for domain, result in results['results'].items():
            print_single_domain_result(domain, result)
            print("-" * 40)
    else:
        # Single domain result
        domain = results.get('domain', 'Unknown')
        print_single_domain_result(domain, results)


def print_single_domain_result(domain: str, result: dict):
    """Print results for a single domain"""
    print(f"Domain: {domain}")
    
    if 'error' in result:
        print(f"❌ Error: {result['error']}")
        return
    
    if not result.get('domain_live', True):
        print("❌ Domain not live")
        return
    
    print(f"✅ Domain is live")
    
    # MX Records
    mx_count = result.get('mx_record_count', result.get('mx_count', 0))
    if mx_count > 0:
        print(f"📧 MX Records: {mx_count}")
        if 'mx_records' in result:
            for mx in result['mx_records'][:3]:  # Show first 3
                print(f"   Priority {mx['priority']}: {mx['hostname']}")
    else:
        print("❌ No MX records found")
    
    # SPF
    if result.get('spf_record') or result.get('has_spf'):
        status = "✅ Valid" if result.get('spf_valid') else "❌ Invalid"
        policy = result.get('spf_policy', 'Unknown')
        print(f"🔒 SPF: {status} (Policy: {policy})")
        if result.get('spf_errors'):
            for error in result['spf_errors']:
                print(f"   Error: {error}")
    else:
        print("❌ No SPF record found")
    
    # DMARC
    if result.get('dmarc_record') or result.get('has_dmarc'):
        status = "✅ Valid" if result.get('dmarc_valid') else "❌ Invalid"
        policy = result.get('dmarc_policy', 'Unknown')
        print(f"🛡️  DMARC: {status} (Policy: {policy})")
        if result.get('dmarc_errors'):
            for error in result['dmarc_errors']:
                print(f"   Error: {error}")
    else:
        print("❌ No DMARC record found")
    
    # DNSSEC
    if result.get('dnssec_enabled'):
        security_score = result.get('dnssec_security_score', 'not_analyzed')
        score_emoji = {
            'excellent': '🟢',
            'good': '🟡', 
            'acceptable': '🟠',
            'warnings_found': '🟠',
            'issues_found': '🔴',
            'error': '❌',
            'not_analyzed': '❔'
        }.get(security_score, '❔')
        
        print(f"🔐 DNSSEC: ✅ Enabled {score_emoji} Security: {security_score}")
        
        # Show security issues
        security_issues = result.get('dnssec_security_issues', [])
        if security_issues:
            print("   🚨 Security Issues:")
            for issue in security_issues[:3]:  # Show first 3 issues
                print(f"      • {issue}")
            if len(security_issues) > 3:
                print(f"      ... and {len(security_issues) - 3} more issues")
        
        # Show security warnings
        security_warnings = result.get('dnssec_security_warnings', [])
        if security_warnings:
            print("   ⚠️  Security Warnings:")
            for warning in security_warnings[:2]:  # Show first 2 warnings
                print(f"      • {warning}")
            if len(security_warnings) > 2:
                print(f"      ... and {len(security_warnings) - 2} more warnings")
        
        # Show recommendations
        recommendations = result.get('dnssec_security_recommendations', [])
        if recommendations:
            print("   💡 Recommendations:")
            for rec in recommendations[:2]:  # Show first 2 recommendations
                print(f"      • {rec}")
            if len(recommendations) > 2:
                print(f"      ... and {len(recommendations) - 2} more recommendations")
        
        # Chain validation status (if available)
        if result.get('dnssec_chain_valid') is not None:
            chain_status = "✅ Valid" if result.get('dnssec_chain_valid') else "❌ Invalid"
            print(f"   Chain validation: {chain_status}")
        
        # Upstream DNSSEC analysis (if available)
        upstream_analysis = result.get('upstream_dnssec_analysis')
        if upstream_analysis and not upstream_analysis.get('error'):
            total_zones = upstream_analysis.get('total_zones_analyzed', 0)
            zones_with_issues = len(upstream_analysis.get('zones_with_issues', []))
            zones_with_warnings = len(upstream_analysis.get('zones_with_warnings', []))
            
            print(f"   🔗 Upstream Analysis: {total_zones} zones checked")
            
            if zones_with_issues > 0:
                print(f"   🚨 Upstream Issues: {zones_with_issues} zones have security issues")
                for issue in upstream_analysis.get('chain_security_issues', [])[:3]:
                    print(f"      • {issue}")
                if len(upstream_analysis.get('chain_security_issues', [])) > 3:
                    print(f"      ... and {len(upstream_analysis.get('chain_security_issues', [])) - 3} more issues")
            
            if zones_with_warnings > 0:
                print(f"   ⚠️  Upstream Warnings: {zones_with_warnings} zones have warnings")
                for warning in upstream_analysis.get('chain_security_warnings', [])[:2]:
                    print(f"      • {warning}")
                if len(upstream_analysis.get('chain_security_warnings', [])) > 2:
                    print(f"      ... and {len(upstream_analysis.get('chain_security_warnings', [])) - 2} more warnings")
            
            if not zones_with_issues and not zones_with_warnings:
                print("   ✅ Upstream zones: No security issues found")
                
        elif upstream_analysis and upstream_analysis.get('error'):
            print(f"   ❌ Upstream analysis failed: {upstream_analysis['error']}")
    else:
        print("❌ DNSSEC: Not enabled")
    
    # SMTP (for active scans)
    if result.get('scan_type') == 'active':
        if result.get('has_smtp_connection'):
            print("📨 SMTP: ✅ Connection successful")
            if result.get('supports_starttls'):
                starttls_status = "✅ Works" if result.get('starttls_works') else "❌ Failed"
                print(f"   STARTTLS: {starttls_status}")
        else:
            print("❌ SMTP: Connection failed")


def scan_domain(domain: str, scan_type: str, timeout: float, output_format: str, dns_servers: Optional[List[str]] = None, check_upstream: bool = False):
    """Scan a single domain"""
    scanner = BasicSecurityScanner(timeout=timeout, dns_servers=dns_servers)
    
    try:
        if scan_type == "passive":
            result = scanner.passive_scan(domain)
        else:
            result = scanner.active_scan(domain)
        
        # Add upstream DNSSEC analysis if requested
        if check_upstream and result.get('dnssec_enabled'):
            try:
                upstream_analysis = scanner.analyze_dnssec_upstream_security(domain, check_upstream=True)
                result['upstream_dnssec_analysis'] = upstream_analysis
            except Exception as e:
                logger.error(f"Upstream DNSSEC analysis failed for {domain}: {str(e)}")
                result['upstream_dnssec_analysis'] = {
                    'error': f"Upstream analysis failed: {str(e)}"
                }
        
        print_results(result, output_format)
        
        # Return exit code based on issues found
        issues = 0
        if not result.get('spf_valid', True):
            issues += 1
        if not result.get('dmarc_valid', True):
            issues += 1
        if not result.get('dnssec_enabled', True):
            issues += 1
        
        # Add upstream issues to exit code
        upstream_analysis = result.get('upstream_dnssec_analysis', {})
        if upstream_analysis.get('zones_with_issues'):
            issues += 1
        
        return min(issues, 3)  # Cap at 3 for exit code
        
    except Exception as e:
        print(f"Error scanning {domain}: {e}", file=sys.stderr)
        return 1


def scan_multiple_domains(domains: List[str], scan_type: str, timeout: float, output_format: str, dns_servers: Optional[List[str]] = None):
    """Scan multiple domains"""
    scanner = BasicSecurityScanner(timeout=timeout, dns_servers=dns_servers)
    
    try:
        result = scanner.scan_multiple_domains(domains, scan_type)
        print_results(result, output_format)
        
        # Return exit code based on failed scans
        return min(result['failed_scans'], 3)
        
    except Exception as e:
        print(f"Error scanning domains: {e}", file=sys.stderr)
        return 1


def quick_check_domains(domains: List[str], check_types: List[str], output_format: str, dns_servers: Optional[List[str]] = None):
    """Quick check multiple domains"""
    scanner = BasicSecurityScanner(timeout=2.0, dns_servers=dns_servers)
    
    try:
        result = scanner.quick_domain_check(domains, check_types)
        print_results(result, output_format)
        
        return min(result['failed_checks'], 3)
        
    except Exception as e:
        print(f"Error in quick check: {e}", file=sys.stderr)
        return 1


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Basic Security Scanner - DNS and Email Security Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  basicsec example.com                           # Passive scan of single domain
  basicsec example.com --active                  # Active scan with SMTP tests
  basicsec example.com google.com --multiple     # Scan multiple domains
  basicsec example.com --quick --checks live mx  # Quick checks only
  basicsec example.com --json                    # Output in JSON format
  basicsec --domains-file domains.txt            # Scan domains from file
  basicsec --domains-file domains.txt --quick    # Quick scan from file
  basicsec example.com --check-upstream          # Check upstream DNSSEC zones
        """
    )
    
    parser.add_argument('domains', nargs='*', help='Domain(s) to scan')
    
    # Scan type options
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('--active', action='store_true', 
                           help='Perform active scan (includes SMTP tests)')
    scan_group.add_argument('--passive', action='store_true', 
                           help='Perform passive scan (DNS only, default)')
    scan_group.add_argument('--quick', action='store_true',
                           help='Quick check mode (fastest)')
    
    # Multiple domain handling
    parser.add_argument('--multiple', action='store_true',
                       help='Scan multiple domains (when more than one domain provided)')
    parser.add_argument('--domains-file', type=str, metavar='FILE',
                       help='Read list of domains from file (one domain per line)')
    
    # Quick check options
    parser.add_argument('--checks', nargs='+', 
                       choices=['live', 'mx', 'spf', 'dmarc', 'dnssec'],
                       default=['live', 'mx', 'spf', 'dmarc', 'dnssec'],
                       help='Types of quick checks to perform')
    
    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--timeout', type=float, default=5.0,
                       help='DNS timeout in seconds (default: 5.0)')
    
    # DNS options
    parser.add_argument('--dns-servers', nargs='+', 
                       help='Custom DNS servers to use (e.g., --dns-servers 8.8.8.8 1.1.1.1)')
    
    # DNSSEC options
    parser.add_argument('--check-upstream', action='store_true',
                       help='Check DNSSEC security of upstream zones (parent zones up to root)')
    
    # Logging
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Handle domain input - either from command line or file
    domains = []
    
    if args.domains_file:
        # Read domains from file
        domains = read_domains_from_file(args.domains_file)
        if not domains:
            print("Error: No valid domains found in file", file=sys.stderr)
            sys.exit(1)
    elif args.domains:
        # Use domains from command line
        domains = args.domains
    else:
        # No domains provided
        print("Error: Must specify domains either via command line or --domains-file", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    
    # Determine output format
    output_format = "json" if args.json else "text"
    
    # Determine scan type
    if args.quick:
        exit_code = quick_check_domains(domains, args.checks, output_format, args.dns_servers)
    elif len(domains) > 1 and (args.multiple or len(domains) > 1):
        scan_type = "active" if args.active else "passive"
        exit_code = scan_multiple_domains(domains, scan_type, args.timeout, output_format, args.dns_servers)
    else:
        # Single domain scan
        scan_type = "active" if args.active else "passive"
        exit_code = scan_domain(domains[0], scan_type, args.timeout, output_format, args.dns_servers, args.check_upstream)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()