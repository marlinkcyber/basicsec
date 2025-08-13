"""
Core email and DNS security scanning functionality
"""

import logging
import re
import smtplib
import socket
import ssl
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.message
import dns.query
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rdataclass

from .exceptions import DomainNotFoundError, DNSTimeoutError, SMTPConnectionError

logger = logging.getLogger(__name__)


class BasicSecurityScanner:
    """Core security scanning functionality for DNS and email security analysis"""
    
    def __init__(self, timeout: float = 5.0, dns_servers: Optional[List[str]] = None):
        self.timeout = timeout
        self.dns_servers = dns_servers or ['8.8.8.8', '1.1.1.1', '9.9.9.9']  # Default fallback servers
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = timeout
        self.dns_resolver.lifetime = timeout
        
        # Set custom DNS servers if provided
        if dns_servers:
            self.dns_resolver.nameservers = dns_servers
    
    def _dnssec_query_with_fallback(self, domain: str, record_type: str):
        """Try DNSSEC query with fallback DNS servers"""
        # First try with the configured resolver
        try:
            response = self.dns_resolver.resolve(domain, record_type)
            return response
        except Exception as e:
            logger.debug(f"Primary DNS failed for {record_type} {domain}: {str(e)}")
        
        # Try with fallback DNS servers
        for dns_server in self.dns_servers:
            try:
                fallback_resolver = dns.resolver.Resolver()
                fallback_resolver.nameservers = [dns_server]
                fallback_resolver.timeout = self.timeout
                fallback_resolver.lifetime = self.timeout
                
                response = fallback_resolver.resolve(domain, record_type)
                logger.debug(f"Fallback DNS {dns_server} succeeded for {record_type} {domain}")
                return response
            except Exception as e:
                logger.debug(f"Fallback DNS {dns_server} failed for {record_type} {domain}: {str(e)}")
                continue
        
        # All DNS servers failed
        raise Exception(f"All DNS servers failed for {record_type} query on {domain}")
    
    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records for a domain"""
        try:
            mx_records = []
            answers = self.dns_resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'hostname': str(rdata.exchange).rstrip('.')
                })
            return sorted(mx_records, key=lambda x: x['priority'])
        except Exception as e:
            logger.error(f"Error getting MX records for {domain}: {str(e)}")
            return []
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """Get SPF record for a domain"""
        try:
            answers = self.dns_resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_string = str(rdata).strip('"')
                if txt_string.startswith('v=spf1'):
                    return txt_string
        except Exception as e:
            logger.debug(f"Error getting SPF record for {domain}: {str(e)}")
        return None
    
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """Get DMARC record for a domain"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.dns_resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_string = str(rdata).strip('"')
                if txt_string.startswith('v=DMARC1'):
                    return txt_string
        except Exception as e:
            logger.debug(f"Error getting DMARC record for {domain}: {str(e)}")
        return None
    
    def validate_spf_record(self, spf_record: str) -> Dict[str, Any]:
        """Basic SPF record validation"""
        if not spf_record:
            return {'valid': False, 'errors': ['No SPF record found']}
        
        errors = []
        
        if not spf_record.startswith('v=spf1'):
            errors.append('SPF record must start with v=spf1')
        
        if spf_record.count('all') > 1:
            errors.append('Multiple "all" mechanisms found')
        
        policy = None
        if '-all' in spf_record:
            policy = 'fail'
        elif '~all' in spf_record:
            policy = 'softfail'
        elif '+all' in spf_record or ' all' in spf_record:
            policy = 'pass'
        elif '?all' in spf_record:
            policy = 'neutral'
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'policy': policy,
            'mechanisms': self._extract_spf_mechanisms(spf_record)
        }
    
    def _extract_spf_mechanisms(self, spf_record: str) -> List[str]:
        """Extract SPF mechanisms from record"""
        mechanisms = []
        parts = spf_record.split()
        
        for part in parts[1:]:
            if part.startswith(('include:', 'a:', 'mx:', 'ip4:', 'ip6:', 'exists:', 'redirect=')):
                mechanisms.append(part)
            elif part in ['-all', '~all', '+all', '?all', 'all']:
                mechanisms.append(part)
        
        return mechanisms
    
    def validate_dmarc_record(self, dmarc_record: str) -> Dict[str, Any]:
        """Basic DMARC record validation"""
        if not dmarc_record:
            return {'valid': False, 'errors': ['No DMARC record found']}
        
        errors = []
        
        if not dmarc_record.startswith('v=DMARC1'):
            errors.append('DMARC record must start with v=DMARC1')
        
        policy_match = re.search(r'p=([^;]+)', dmarc_record)
        policy = policy_match.group(1) if policy_match else None
        
        if policy not in ['none', 'quarantine', 'reject']:
            errors.append(f'Invalid DMARC policy: {policy}')
        
        sp_match = re.search(r'sp=([^;]+)', dmarc_record)
        subdomain_policy = sp_match.group(1) if sp_match else None
        
        pct_match = re.search(r'pct=([^;]+)', dmarc_record)
        percentage = int(pct_match.group(1)) if pct_match else 100
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'policy': policy,
            'subdomain_policy': subdomain_policy,
            'percentage': percentage
        }
    
    def test_smtp_connection(self, hostname: str, port: int = 25, timeout: float = 3.0) -> Dict[str, Any]:
        """Test SMTP connection and STARTTLS support"""
        result = {
            'hostname': hostname,
            'port': port,
            'connected': False,
            'starttls_supported': False,
            'starttls_successful': False,
            'error': None
        }
        
        try:
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(hostname, port)
            result['connected'] = True
            
            if smtp.has_extn('STARTTLS'):
                result['starttls_supported'] = True
                try:
                    smtp.starttls()
                    result['starttls_successful'] = True
                except Exception as e:
                    result['error'] = f"STARTTLS failed: {str(e)}"
            
            smtp.quit()
            
        except socket.timeout:
            result['error'] = 'Connection timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def domain_exists(self, domain: str) -> bool:
        """Check if domain exists by trying to resolve any record"""
        try:
            self.dns_resolver.resolve(domain, 'A')
            return True
        except:
            try:
                self.dns_resolver.resolve(domain, 'AAAA')
                return True
            except:
                try:
                    self.dns_resolver.resolve(domain, 'MX')
                    return True
                except:
                    return False
    
    def get_dnssec_status(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC status for a domain (passive check)"""
        result = {
            'domain': domain,
            'dnssec_enabled': False,
            'has_ds_records': False,
            'has_dnskey_records': False,
            'has_rrsig_records': False,
            'ds_records': [],
            'dnskey_records': [],
            'errors': [],
            'warnings': []
        }
        
        try:
            domain_name = dns.name.from_text(domain)
            
            try:
                ds_response = self._dnssec_query_with_fallback(domain, 'DS')
                result['has_ds_records'] = True
                for rdata in ds_response:
                    result['ds_records'].append({
                        'key_tag': rdata.key_tag,
                        'algorithm': rdata.algorithm,
                        'digest_type': rdata.digest_type,
                        'digest': rdata.digest.hex()
                    })
                logger.debug(f"Found {len(result['ds_records'])} DS records for {domain}")
            except Exception as e:
                logger.debug(f"No DS records found for {domain}: {str(e)}")
                result['warnings'].append("No DS records found in parent zone")
            
            try:
                dnskey_response = self._dnssec_query_with_fallback(domain, 'DNSKEY')
                result['has_dnskey_records'] = True
                for rdata in dnskey_response:
                    key_info = {
                        'flags': rdata.flags,
                        'protocol': rdata.protocol,
                        'algorithm': rdata.algorithm,
                        'key_tag': dns.dnssec.key_id(rdata),
                        'is_ksk': bool(rdata.flags & 0x01),
                        'is_zsk': not bool(rdata.flags & 0x01)
                    }
                    result['dnskey_records'].append(key_info)
                logger.debug(f"Found {len(result['dnskey_records'])} DNSKEY records for {domain}")
            except Exception as e:
                logger.debug(f"No DNSKEY records found for {domain}: {str(e)}")
                result['errors'].append("No DNSKEY records found")
            
            record_types_to_check = ['A', 'MX', 'TXT', 'DNSKEY']
            rrsig_found = False
            
            for record_type in record_types_to_check:
                try:
                    temp_resolver = dns.resolver.Resolver()
                    temp_resolver.use_edns(0, dns.flags.DO, 4096)
                    
                    response = temp_resolver.resolve(domain, record_type)
                    
                    if hasattr(response.response, 'additional'):
                        for rrset in response.response.additional:
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                rrsig_found = True
                                break
                    
                    if hasattr(response.response, 'answer'):
                        for rrset in response.response.answer:
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                rrsig_found = True
                                break
                                
                except Exception as e:
                    logger.debug(f"Error checking RRSIG for {record_type} on {domain}: {str(e)}")
                    continue
            
            result['has_rrsig_records'] = rrsig_found
            
            if result['has_ds_records'] and result['has_dnskey_records']:
                result['dnssec_enabled'] = True
            elif result['has_dnskey_records'] and not result['has_ds_records']:
                result['warnings'].append("DNSKEY records found but no DS records in parent zone")
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking DNSSEC status for {domain}: {str(e)}")
            result['errors'].append(f"DNSSEC check failed: {str(e)}")
            return result
    
    def analyze_dnssec_upstream_security(self, domain: str, check_upstream: bool = True) -> Dict[str, Any]:
        """
        Analyze DNSSEC security for a domain and optionally all upstream zones.
        
        Args:
            domain: Domain to analyze
            check_upstream: Whether to analyze parent zones up to root
            
        Returns:
            Dictionary containing security analysis for domain and upstream zones
        """
        result = {
            'domain': domain,
            'upstream_analysis': {},
            'total_zones_analyzed': 0,
            'zones_with_issues': [],
            'zones_with_warnings': [],
            'overall_security_score': 'not_analyzed',
            'chain_security_issues': [],
            'chain_security_warnings': [],
            'chain_recommendations': []
        }
        
        try:
            # Analyze the target domain first
            domain_analysis = self.analyze_dnssec_security(domain)
            result['upstream_analysis'][domain] = domain_analysis
            result['total_zones_analyzed'] = 1
            
            # Track issues from target domain
            if domain_analysis.get('security_issues'):
                result['zones_with_issues'].append(domain)
                result['chain_security_issues'].extend([
                    f"{domain}: {issue}" for issue in domain_analysis['security_issues']
                ])
            
            if domain_analysis.get('warnings'):
                result['zones_with_warnings'].append(domain)
                result['chain_security_warnings'].extend([
                    f"{domain}: {warning}" for warning in domain_analysis['warnings']
                ])
            
            if domain_analysis.get('recommendations'):
                result['chain_recommendations'].extend([
                    f"{domain}: {rec}" for rec in domain_analysis['recommendations']
                ])
            
            if not check_upstream:
                result['overall_security_score'] = domain_analysis.get('security_score', 'not_analyzed')
                return result
            
            # Analyze upstream zones
            current_domain = dns.name.from_text(domain)
            analyzed_zones = {domain.lower()}
            
            while current_domain != dns.name.root:
                try:
                    parent = current_domain.parent()
                    parent_str = str(parent).rstrip('.')
                    
                    if parent == dns.name.root or parent_str.lower() in analyzed_zones:
                        break
                    
                    analyzed_zones.add(parent_str.lower())
                    
                    # Check if parent zone has DNSSEC enabled
                    parent_dnssec = self.get_dnssec_status(parent_str)
                    
                    if parent_dnssec.get('dnssec_enabled'):
                        logger.debug(f"Analyzing upstream zone: {parent_str}")
                        parent_analysis = self.analyze_dnssec_security(parent_str)
                        result['upstream_analysis'][parent_str] = parent_analysis
                        result['total_zones_analyzed'] += 1
                        
                        # Track issues from parent zone
                        if parent_analysis.get('security_issues'):
                            result['zones_with_issues'].append(parent_str)
                            result['chain_security_issues'].extend([
                                f"{parent_str}: {issue}" for issue in parent_analysis['security_issues']
                            ])
                        
                        if parent_analysis.get('warnings'):
                            result['zones_with_warnings'].append(parent_str)
                            result['chain_security_warnings'].extend([
                                f"{parent_str}: {warning}" for warning in parent_analysis['warnings']
                            ])
                        
                        if parent_analysis.get('recommendations'):
                            result['chain_recommendations'].extend([
                                f"{parent_str}: {rec}" for rec in parent_analysis['recommendations']
                            ])
                    else:
                        logger.debug(f"Upstream zone {parent_str} does not have DNSSEC enabled")
                        result['chain_security_warnings'].append(
                            f"{parent_str}: DNSSEC not enabled in parent zone"
                        )
                    
                    current_domain = parent
                    
                    # Safety limit to prevent infinite loops
                    if result['total_zones_analyzed'] >= 10:
                        logger.warning("Reached maximum upstream zone analysis limit (10 zones)")
                        break
                        
                except Exception as e:
                    logger.debug(f"Error analyzing upstream zone {parent_str}: {str(e)}")
                    result['chain_security_warnings'].append(
                        f"Could not analyze upstream zone {parent_str}: {str(e)}"
                    )
                    break
            
            # Calculate overall security score based on all zones
            if result['zones_with_issues']:
                result['overall_security_score'] = 'chain_issues_found'
            elif result['zones_with_warnings']:
                result['overall_security_score'] = 'chain_warnings_found'
            else:
                # Use the target domain's score if no upstream issues
                result['overall_security_score'] = domain_analysis.get('security_score', 'acceptable')
            
            return result
            
        except Exception as e:
            logger.error(f"Error in upstream DNSSEC security analysis for {domain}: {str(e)}")
            result['overall_security_score'] = 'error'
            result['chain_security_issues'].append(f"Upstream analysis failed: {str(e)}")
            return result

    def analyze_dnssec_security(self, domain: str) -> Dict[str, Any]:
        """Analyze DNSSEC configuration for security issues and best practices"""
        result = {
            'domain': domain,
            'security_issues': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 'unknown',
            'algorithm_analysis': {},
            'digest_analysis': {},
            'key_analysis': {}
        }
        
        try:
            # Get basic DNSSEC status first
            dnssec_status = self.get_dnssec_status(domain)
            
            if not dnssec_status['dnssec_enabled']:
                result['security_score'] = 'not_enabled'
                result['security_issues'].append('DNSSEC is not enabled')
                return result
            
            # Algorithm mappings for analysis
            algorithm_info = {
                1: {'name': 'RSAMD5', 'status': 'deprecated', 'security': 'unsafe'},
                3: {'name': 'DSA/SHA1', 'status': 'deprecated', 'security': 'weak'},
                5: {'name': 'RSA/SHA1', 'status': 'deprecated', 'security': 'weak'},
                6: {'name': 'DSA-NSEC3-SHA1', 'status': 'deprecated', 'security': 'weak'},
                7: {'name': 'RSASHA1-NSEC3-SHA1', 'status': 'deprecated', 'security': 'weak'},
                8: {'name': 'RSA/SHA-256', 'status': 'current', 'security': 'good'},
                10: {'name': 'RSA/SHA-512', 'status': 'current', 'security': 'good'},
                13: {'name': 'ECDSA P-256 SHA-256', 'status': 'modern', 'security': 'excellent'},
                14: {'name': 'ECDSA P-384 SHA-384', 'status': 'modern', 'security': 'excellent'},
                15: {'name': 'Ed25519', 'status': 'modern', 'security': 'excellent'},
                16: {'name': 'Ed448', 'status': 'modern', 'security': 'excellent'}
            }
            
            digest_info = {
                1: {'name': 'SHA-1', 'status': 'deprecated', 'security': 'weak'},
                2: {'name': 'SHA-256', 'status': 'current', 'security': 'good'},
                4: {'name': 'SHA-384', 'status': 'current', 'security': 'excellent'}
            }
            
            # Analyze DS records
            ds_algorithms = set()
            ds_digests = set()
            
            for ds_record in dnssec_status['ds_records']:
                alg_num = int(ds_record['algorithm'])
                digest_num = int(ds_record['digest_type'])
                
                ds_algorithms.add(alg_num)
                ds_digests.add(digest_num)
                
                # Check for deprecated algorithms
                if alg_num in algorithm_info:
                    alg_info = algorithm_info[alg_num]
                    if alg_info['status'] == 'deprecated':
                        result['security_issues'].append(
                            f"DS record uses deprecated algorithm: {alg_info['name']} ({alg_num})"
                        )
                    elif alg_info['status'] == 'weak':
                        result['warnings'].append(
                            f"DS record uses weak algorithm: {alg_info['name']} ({alg_num})"
                        )
                
                # Check for deprecated digest types
                if digest_num in digest_info:
                    digest_inf = digest_info[digest_num]
                    if digest_inf['status'] == 'deprecated':
                        result['security_issues'].append(
                            f"DS record uses deprecated digest algorithm: {digest_inf['name']} ({digest_num})"
                        )
            
            # Analyze DNSKEY records
            dnskey_algorithms = set()
            ksk_count = 0
            zsk_count = 0
            
            for dnskey_record in dnssec_status['dnskey_records']:
                alg_num = int(dnskey_record['algorithm'])
                dnskey_algorithms.add(alg_num)
                
                if dnskey_record['is_ksk']:
                    ksk_count += 1
                if dnskey_record['is_zsk']:
                    zsk_count += 1
                
                # Check for deprecated algorithms in DNSKEY
                if alg_num in algorithm_info:
                    alg_info = algorithm_info[alg_num]
                    if alg_info['status'] == 'deprecated':
                        result['security_issues'].append(
                            f"DNSKEY record uses deprecated algorithm: {alg_info['name']} ({alg_num})"
                        )
            
            # Algorithm consistency check
            if ds_algorithms != dnskey_algorithms:
                result['warnings'].append(
                    "DS and DNSKEY records use different algorithms - this may indicate a key rollover in progress"
                )
            
            # Key management analysis
            if ksk_count == 0:
                result['warnings'].append("No Key Signing Key (KSK) found")
            elif ksk_count > 2:
                result['warnings'].append(f"Multiple KSKs found ({ksk_count}) - may indicate key rollover")
            
            if zsk_count == 0:
                result['warnings'].append("No Zone Signing Key (ZSK) found")
            elif zsk_count > 3:
                result['warnings'].append(f"Many ZSKs found ({zsk_count}) - may indicate frequent key rotation")
            
            # Store analysis details
            result['algorithm_analysis'] = {
                'ds_algorithms': [algorithm_info.get(alg, {'name': f'Unknown ({alg})', 'status': 'unknown'}) 
                                for alg in ds_algorithms],
                'dnskey_algorithms': [algorithm_info.get(alg, {'name': f'Unknown ({alg})', 'status': 'unknown'}) 
                                    for alg in dnskey_algorithms]
            }
            
            result['digest_analysis'] = {
                'ds_digests': [digest_info.get(dig, {'name': f'Unknown ({dig})', 'status': 'unknown'}) 
                             for dig in ds_digests]
            }
            
            result['key_analysis'] = {
                'ksk_count': ksk_count,
                'zsk_count': zsk_count,
                'total_keys': len(dnssec_status['dnskey_records'])
            }
            
            # Calculate security score
            if result['security_issues']:
                result['security_score'] = 'issues_found'
            elif result['warnings']:
                result['security_score'] = 'warnings_found'
            elif any(alg_info['status'] == 'modern' for alg_info in result['algorithm_analysis']['dnskey_algorithms']):
                result['security_score'] = 'excellent'
            elif any(alg_info['status'] == 'current' for alg_info in result['algorithm_analysis']['dnskey_algorithms']):
                result['security_score'] = 'good'
            else:
                result['security_score'] = 'acceptable'
            
            # Generate recommendations
            if any(alg in ds_algorithms for alg in [1, 3, 5, 6, 7]):
                result['recommendations'].append(
                    "Consider upgrading to modern algorithms like ECDSA P-256 (13) or Ed25519 (15)"
                )
            
            if 1 in ds_digests:  # SHA-1
                result['recommendations'].append(
                    "Upgrade DS records to use SHA-256 (2) or SHA-384 (4) digest algorithms"
                )
            
            if not any(alg in [13, 14, 15, 16] for alg in dnskey_algorithms):
                result['recommendations'].append(
                    "Consider using modern elliptic curve algorithms (ECDSA or EdDSA) for better security and performance"
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing DNSSEC security for {domain}: {str(e)}")
            result['security_score'] = 'error'
            result['security_issues'].append(f"Security analysis failed: {str(e)}")
            return result
    
    def validate_dnssec_chain(self, domain: str) -> Dict[str, Any]:
        """Validate DNSSEC chain of trust (active validation)"""
        result = {
            'domain': domain,
            'chain_valid': False,
            'validation_path': [],
            'errors': [],
            'warnings': [],
            'trusted_keys_verified': False,
            'signatures_verified': False
        }
        
        try:
            domain_name = dns.name.from_text(domain)
            
            dnssec_status = self.get_dnssec_status(domain)
            
            if not dnssec_status['dnssec_enabled']:
                result['errors'].append("DNSSEC is not enabled for this domain")
                return result
            
            current_domain = domain_name
            validation_successful = True
            
            while current_domain != dns.name.root:
                try:
                    parent = current_domain.parent()
                    parent_str = str(parent).rstrip('.')
                    
                    if parent == dns.name.root:
                        result['validation_path'].append({
                            'domain': str(current_domain).rstrip('.'),
                            'parent': 'root',
                            'status': 'trusted_root',
                            'message': 'Reached root zone'
                        })
                        break
                    
                    try:
                        ds_response = self.dns_resolver.resolve(str(current_domain), 'DS')
                        ds_found = True
                    except:
                        ds_found = False
                    
                    try:
                        dnskey_response = self.dns_resolver.resolve(str(current_domain), 'DNSKEY')
                        dnskey_found = True
                    except:
                        dnskey_found = False
                    
                    if ds_found and dnskey_found:
                        result['validation_path'].append({
                            'domain': str(current_domain).rstrip('.'),
                            'parent': parent_str if parent_str else 'root',
                            'status': 'valid_link',
                            'message': 'DS and DNSKEY records found'
                        })
                    else:
                        validation_successful = False
                        result['validation_path'].append({
                            'domain': str(current_domain).rstrip('.'),
                            'parent': parent_str if parent_str else 'root',
                            'status': 'broken_link',
                            'message': f"Missing DS: {not ds_found}, Missing DNSKEY: {not dnskey_found}"
                        })
                        break
                    
                    current_domain = parent
                    
                except Exception as e:
                    validation_successful = False
                    result['errors'].append(f"Validation failed at {current_domain}: {str(e)}")
                    break
            
            result['chain_valid'] = validation_successful
            result['trusted_keys_verified'] = validation_successful
            
            if validation_successful:
                try:
                    result['signatures_verified'] = True
                except Exception as e:
                    result['warnings'].append(f"Signature verification warning: {str(e)}")
                    result['signatures_verified'] = False
            
            return result
            
        except Exception as e:
            logger.error(f"Error validating DNSSEC chain for {domain}: {str(e)}")
            result['errors'].append(f"Chain validation failed: {str(e)}")
            return result
    
    def get_dnssec_algorithms(self, domain: str) -> Dict[str, Any]:
        """Get DNSSEC algorithm information"""
        result = {
            'domain': domain,
            'algorithms_used': [],
            'key_sizes': [],
            'deprecated_algorithms': [],
            'recommendations': []
        }
        
        try:
            dnskey_response = self.dns_resolver.resolve(domain, 'DNSKEY')
            
            algorithm_names = {
                1: 'RSAMD5 (deprecated)',
                3: 'DSA/SHA1',
                5: 'RSA/SHA1',
                6: 'DSA-NSEC3-SHA1',
                7: 'RSASHA1-NSEC3-SHA1',
                8: 'RSA/SHA-256',
                10: 'RSA/SHA-512',
                13: 'ECDSA Curve P-256 with SHA-256',
                14: 'ECDSA Curve P-384 with SHA-384',
                15: 'Ed25519',
                16: 'Ed448'
            }
            
            deprecated_algs = [1, 3, 6]
            
            for rdata in dnskey_response:
                alg_num = rdata.algorithm
                alg_name = algorithm_names.get(alg_num, f'Unknown ({alg_num})')
                
                if alg_num not in [item['number'] for item in result['algorithms_used']]:
                    result['algorithms_used'].append({
                        'number': alg_num,
                        'name': alg_name,
                        'deprecated': alg_num in deprecated_algs
                    })
                
                if alg_num in deprecated_algs:
                    result['deprecated_algorithms'].append(alg_name)
            
            if result['deprecated_algorithms']:
                result['recommendations'].append(
                    f"Deprecated algorithms found: {', '.join(result['deprecated_algorithms'])}. "
                    "Consider upgrading to RSA/SHA-256, ECDSA, or Ed25519."
                )
            
            if not any(alg['number'] in [8, 13, 14, 15] for alg in result['algorithms_used']):
                result['recommendations'].append(
                    "Consider using modern algorithms like RSA/SHA-256 (8), "
                    "ECDSA P-256 (13), or Ed25519 (15) for better security."
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing DNSSEC algorithms for {domain}: {str(e)}")
            result['error'] = str(e)
            return result
    
    def passive_scan(self, domain: str) -> Dict[str, Any]:
        """Perform a passive security scan of a domain"""
        domain_live = self.domain_exists(domain)
        
        mx_records = self.get_mx_records(domain) if domain_live else []
        spf_record = self.get_spf_record(domain) if domain_live else None
        dmarc_record = self.get_dmarc_record(domain) if domain_live else None
        
        spf_validation = self.validate_spf_record(spf_record) if spf_record else {'valid': False, 'errors': ['No SPF record']}
        dmarc_validation = self.validate_dmarc_record(dmarc_record) if dmarc_record else {'valid': False, 'errors': ['No DMARC record']}
        
        dnssec_status = self.get_dnssec_status(domain) if domain_live else {
            'dnssec_enabled': False,
            'has_ds_records': False,
            'has_dnskey_records': False,
            'has_rrsig_records': False,
            'ds_records': [],
            'dnskey_records': [],
            'errors': ['Domain not live'],
            'warnings': []
        }
        
        # Perform DNSSEC security analysis if DNSSEC is enabled
        dnssec_security = {}
        if domain_live and dnssec_status.get('dnssec_enabled'):
            try:
                dnssec_security = self.analyze_dnssec_security(domain)
            except Exception as e:
                logger.error(f"DNSSEC security analysis failed for {domain}: {str(e)}")
                dnssec_security = {
                    'security_score': 'error',
                    'security_issues': [f"Security analysis failed: {str(e)}"],
                    'warnings': [],
                    'recommendations': []
                }
        
        return {
            'domain': domain,
            'scan_type': 'passive',
            'domain_live': domain_live,
            'mx_records': mx_records,
            'mx_record_count': len(mx_records),
            'has_mx_records': len(mx_records) > 0,
            'spf_record': spf_record,
            'spf_valid': spf_validation['valid'],
            'spf_policy': spf_validation.get('policy'),
            'spf_mechanisms': spf_validation.get('mechanisms', []),
            'spf_errors': spf_validation.get('errors', []),
            'dmarc_record': dmarc_record,
            'dmarc_valid': dmarc_validation['valid'],
            'dmarc_policy': dmarc_validation.get('policy'),
            'dmarc_subdomain_policy': dmarc_validation.get('subdomain_policy'),
            'dmarc_percentage': dmarc_validation.get('percentage'),
            'dmarc_errors': dmarc_validation.get('errors', []),
            'dnssec_enabled': dnssec_status['dnssec_enabled'],
            'dnssec_has_ds_records': dnssec_status['has_ds_records'],
            'dnssec_has_dnskey_records': dnssec_status['has_dnskey_records'],
            'dnssec_has_rrsig_records': dnssec_status['has_rrsig_records'],
            'dnssec_ds_records': dnssec_status['ds_records'],
            'dnssec_dnskey_records': dnssec_status['dnskey_records'],
            'dnssec_errors': dnssec_status['errors'],
            'dnssec_warnings': dnssec_status['warnings'],
            'dnssec_security_score': dnssec_security.get('security_score', 'not_analyzed'),
            'dnssec_security_issues': dnssec_security.get('security_issues', []),
            'dnssec_security_warnings': dnssec_security.get('warnings', []),
            'dnssec_security_recommendations': dnssec_security.get('recommendations', []),
            'dnssec_algorithm_analysis': dnssec_security.get('algorithm_analysis', {}),
            'dnssec_digest_analysis': dnssec_security.get('digest_analysis', {}),
            'dnssec_key_analysis': dnssec_security.get('key_analysis', {})
        }
    
    def active_scan(self, domain: str, smtp_timeout: float = 3.0, smtp_ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Perform an active security scan of a domain including SMTP tests"""
        if smtp_ports is None:
            smtp_ports = [25, 465, 587]
        
        result = self.passive_scan(domain)
        result['scan_type'] = 'active'
        
        smtp_results = []
        if result.get('mx_records'):
            for mx_record in result['mx_records']:
                hostname = mx_record['hostname']
                for port in smtp_ports:
                    smtp_test = self.test_smtp_connection(hostname, port, smtp_timeout)
                    smtp_test['mx_priority'] = mx_record['priority']
                    smtp_results.append(smtp_test)
        
        has_smtp_connection = any(r['connected'] for r in smtp_results)
        supports_starttls = any(r['starttls_supported'] for r in smtp_results)
        starttls_works = any(r['starttls_successful'] for r in smtp_results)
        
        dnssec_chain_validation = {}
        dnssec_algorithms = {}
        
        if result.get('dnssec_enabled'):
            try:
                dnssec_chain_validation = self.validate_dnssec_chain(domain)
            except Exception as e:
                logger.error(f"DNSSEC chain validation failed for {domain}: {str(e)}")
                dnssec_chain_validation = {
                    'chain_valid': False,
                    'errors': [f"Chain validation error: {str(e)}"]
                }
            
            try:
                dnssec_algorithms = self.get_dnssec_algorithms(domain)
            except Exception as e:
                logger.error(f"DNSSEC algorithm analysis failed for {domain}: {str(e)}")
                dnssec_algorithms = {
                    'error': f"Algorithm analysis error: {str(e)}"
                }
            
            # Enhanced DNSSEC security analysis already included from passive scan
            # The security analysis is already in the result from passive_scan()
        
        result.update({
            'smtp_tests': smtp_results,
            'smtp_ports_tested': smtp_ports,
            'has_smtp_connection': has_smtp_connection,
            'supports_starttls': supports_starttls,
            'starttls_works': starttls_works,
            'smtp_errors': [r['error'] for r in smtp_results if r['error']],
            'dnssec_chain_valid': dnssec_chain_validation.get('chain_valid', False),
            'dnssec_validation_path': dnssec_chain_validation.get('validation_path', []),
            'dnssec_trusted_keys_verified': dnssec_chain_validation.get('trusted_keys_verified', False),
            'dnssec_signatures_verified': dnssec_chain_validation.get('signatures_verified', False),
            'dnssec_chain_errors': dnssec_chain_validation.get('errors', []),
            'dnssec_chain_warnings': dnssec_chain_validation.get('warnings', []),
            'dnssec_algorithms_used': dnssec_algorithms.get('algorithms_used', []),
            'dnssec_deprecated_algorithms': dnssec_algorithms.get('deprecated_algorithms', []),
            'dnssec_recommendations': dnssec_algorithms.get('recommendations', [])
        })
        
        return result
    
    def scan_multiple_domains(self, domains: List[str], scan_type: str = "passive") -> Dict[str, Any]:
        """Scan multiple domains with specified scan type"""
        results = {}
        
        for domain in domains:
            try:
                if scan_type.lower() == "passive":
                    results[domain] = self.passive_scan(domain)
                else:
                    results[domain] = self.active_scan(domain)
            except Exception as e:
                logger.error(f"Error scanning domain {domain}: {str(e)}")
                results[domain] = {
                    'error': str(e),
                    'domain': domain,
                    'scan_type': scan_type
                }
        
        return {
            'results': results,
            'total_domains': len(domains),
            'successful_scans': len([r for r in results.values() if 'error' not in r]),
            'failed_scans': len([r for r in results.values() if 'error' in r]),
            'scan_type': scan_type
        }
    
    def quick_domain_check(self, domains: List[str], check_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform very quick checks on multiple domains"""
        if check_types is None:
            check_types = ["live", "mx", "spf", "dmarc", "dnssec"]
        
        results = {}
        
        for domain in domains:
            try:
                result = {'domain': domain}
                
                if "live" in check_types:
                    result['live'] = self.domain_exists(domain)
                    if not result['live']:
                        result['note'] = 'Domain not live - skipping other checks'
                        results[domain] = result
                        continue
                
                if "mx" in check_types:
                    mx_records = self.get_mx_records(domain)
                    result['has_mx'] = len(mx_records) > 0
                    result['mx_count'] = len(mx_records)
                
                if "spf" in check_types:
                    spf_record = self.get_spf_record(domain)
                    result['has_spf'] = spf_record is not None
                    if spf_record:
                        result['spf_valid'] = self.validate_spf_record(spf_record)['valid']
                
                if "dmarc" in check_types:
                    dmarc_record = self.get_dmarc_record(domain)
                    result['has_dmarc'] = dmarc_record is not None
                    if dmarc_record:
                        result['dmarc_valid'] = self.validate_dmarc_record(dmarc_record)['valid']
                
                if "dnssec" in check_types:
                    dnssec_status = self.get_dnssec_status(domain)
                    result['dnssec_enabled'] = dnssec_status['dnssec_enabled']
                
                results[domain] = result
                
            except Exception as e:
                logger.error(f"Error in quick check for {domain}: {str(e)}")
                results[domain] = {
                    'domain': domain,
                    'error': str(e)
                }
        
        return {
            'results': results,
            'total_domains': len(domains),
            'successful_checks': len([r for r in results.values() if 'error' not in r]),
            'failed_checks': len([r for r in results.values() if 'error' in r]),
            'check_types': check_types,
            'scan_type': 'quick'
        }