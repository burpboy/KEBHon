#!/usr/bin/env python3
"""
passive_osint.py - Automated Passive OSINT Tool
Integrates Shodan, Censys, VirusTotal, and GitHub APIs for passive reconnaissance.
Requires Python 3.8+ and the following libraries:
    pip install requests rich colorama
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError
except ImportError:
    print("Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class Console:
        def print(self, *args, **kwargs):
            print(*args, **kwargs)
        def panel(self, *args, **kwargs):
            return None
    class RichTable:
        def add_column(self, *args, **kwargs): pass
        def add_row(self, *args, **kwargs): pass
        def __str__(self):
            return ""

import colorama
colorama.init(autoreset=True)

# ========================
# Configuration & Logging
# ========================

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_rich_console():
    if HAS_RICH:
        return Console()
    return Console()

console = get_rich_console()

# ========================
# API Client Base Class
# ========================

class APIClient:
    """Base class for API clients."""
    
    def __init__(self, api_key: str, base_url: str = "", timeout: int = 30):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PassiveOSINT/1.0',
            'Accept': 'application/json'
        })
    
    def _request(self, method: str, url: str, params: dict = None, data: dict = None, headers: dict = None) -> dict:
        """Execute HTTP request with error handling."""
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=headers or {},
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP Error: {e}")
            if hasattr(e.response, 'text'):
                logger.debug(f"Response body: {e.response.text[:500]}")
            raise
        except requests.exceptions.Timeout:
            logger.error(f"Timeout connecting to {url}")
            raise
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error to {url}")
            raise
        except ValueError as e:
            logger.error(f"JSON decode error: {e}")
            raise
    
    def close(self):
        self.session.close()


# ========================
# Shodan Client
# ========================

class ShodanClient(APIClient):
    """Client for Shodan API v1.5+."""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, self.BASE_URL, timeout)
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}'
        })
    
    def search_ip(self, ip: str) -> dict:
        """Search for information about a specific IP address."""
        url = f"{self.BASE_URL}/api/rest/info/{ip}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"Shodan IP search failed for {ip}: {e}")
            return {}
    
    def search_domain(self, domain: str) -> dict:
        """Search for information about a domain."""
        url = f"{self.BASE_URL}/api/rest/domain/{domain}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"Shodan domain search failed for {domain}: {e}")
            return {}
    
    def search_query(self, query: str, limit: int = 100) -> dict:
        """Perform a general search query."""
        url = f"{self.BASE_URL}/api/rest/search"
        params = {'query': query, 'limit': min(limit, 1000)}
        try:
            return self._request('GET', url, params=params)
        except Exception as e:
            logger.error(f"Shodan query search failed: {e}")
            return {}
    
    def get_host(self, ip: str) -> dict:
        """Get detailed host information."""
        url = f"{self.BASE_URL}/api/rest/host/{ip}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"Shodan host lookup failed for {ip}: {e}")
            return {}
    
    def get_ports(self, ip: str) -> list:
        """Get open ports for an IP."""
        host_data = self.get_host(ip)
        if not host_data:
            return []
        return host_data.get('ports', [])
    
    def get_vulns(self, ip: str) -> list:
        """Get vulnerabilities for an IP."""
        host_data = self.get_host(ip)
        if not host_data:
            return []
        vulns = host_data.get('vulns', [])
        # Filter out already patched ones
        return [v for v in vulns if v.upper() != 'PATCHED']
    
    def check_api_credits(self) -> int:
        """Check remaining API credits."""
        url = f"{self.BASE_URL}/api-info"
        try:
            data = self._request('GET', url)
            return data.get('credits', 0)
        except Exception as e:
            logger.warning(f"Could not check Shodan credits: {e}")
            return -1


# ========================
# Censys Client
# ========================

class CensysClient(APIClient):
    """Client for Censys API."""
    
    BASE_URL = "https://search.censys.io/api/v2"
    
    def __init__(self, api_id: str, api_secret: str, timeout: int = 30):
        super().__init__(api_id, self.BASE_URL, timeout)
        self.api_secret = api_secret
        self.session.auth = (api_id, api_secret)
    
    def search_hosts(self, query: str, per_page: int = 100) -> dict:
        """Search for hosts matching a query."""
        url = f"{self.BASE_URL}/hosts/search"
        data = {
            'q': query,
            'per_page': min(per_page, 100),
            'fields': ['ip', 'services.product', 'services.http.server', 'location.country']
        }
        try:
            return self._request('POST', url, data=data)
        except Exception as e:
            logger.error(f"Censys host search failed: {e}")
            return {}
    
    def get_host_details(self, ip: str) -> dict:
        """Get detailed information about a specific host."""
        url = f"{self.BASE_URL}/hosts/{ip}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"Censys host details failed for {ip}: {e}")
            return {}
    
    def get_certificates(self, query: str, per_page: int = 100) -> dict:
        """Search for certificates."""
        url = f"{self.BASE_URL}/certificates/search"
        data = {
            'q': query,
            'per_page': min(per_page, 100)
        }
        try:
            return self._request('POST', url, data=data)
        except Exception as e:
            logger.error(f"Censys certificate search failed: {e}")
            return {}
    
    def get_certificate_by_hash(self, hash_value: str) -> dict:
        """Get certificate by its SHA-256 hash."""
        url = f"{self.BASE_URL}/certificates/{hash_value}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"Censys certificate lookup failed: {e}")
            return {}
    
    def check_api_limits(self) -> dict:
        """Check API usage limits."""
        url = f"{self.BASE_URL}/usage"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.warning(f"Could not check Censys limits: {e}")
            return {}


# ========================
# VirusTotal Client
# ========================

class VirusTotalClient(APIClient):
    """Client for VirusTotal API v3."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, self.BASE_URL, timeout)
        self.session.headers.update({
            'x-apikey': api_key
        })
    
    def analyze_file(self, file_path: str) -> dict:
        """Analyze a file by uploading it."""
        url = f"{self.BASE_URL}/files"
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = self.session.post(url, files=files, timeout=self.timeout)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"VT file analysis failed for {file_path}: {e}")
            return {}
    
    def get_file_report(self, hash_value: str) -> dict:
        """Get report for a file by its hash (MD5, SHA-1, SHA-256)."""
        url = f"{self.BASE_URL}/files/{hash_value}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"VT file report failed for {hash_value}: {e}")
            return {}
    
    def analyze_url(self, url: str) -> dict:
        """Analyze a URL."""
        url_encoded = url.replace('http://', '').replace('https://', '')
        endpoint = f"{self.BASE_URL}/urls/url"
        data = {'url': url}
        try:
            response = self.session.post(endpoint, json=data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"VT URL analysis failed for {url}: {e}")
            return {}
    
    def get_url_report(self, url_id: str) -> dict:
        """Get report for a URL by its ID."""
        url = f"{self.BASE_URL}/urls/{url_id}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"VT URL report failed: {e}")
            return {}
    
    def get_ip_report(self, ip: str) -> dict:
        """Get report for an IP address."""
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"VT IP report failed for {ip}: {e}")
            return {}
    
    def get_domain_report(self, domain: str) -> dict:
        """Get report for a domain."""
        url = f"{self.BASE_URL}/domains/{domain}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"VT domain report failed for {domain}: {e}")
            return {}
    
    def get_relationship(self, resource_id: str, relationship: str, limit: int = 40) -> dict:
        """Get related resources."""
        url = f"{self.BASE_URL}/{resource_id}/{relationship}?limit={min(limit, 40)}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"VT relationship fetch failed: {e}")
            return {}
    
    def check_api_quota(self) -> dict:
        """Check API quota usage."""
        url = f"{self.BASE_URL}/users/self"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.warning(f"Could not check VT quota: {e}")
            return {}


# ========================
# GitHub Client
# ========================

class GitHubClient(APIClient):
    """Client for GitHub API v3."""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: str = "", timeout: int = 30):
        super().__init__(token, self.BASE_URL, timeout)
        if token:
            self.session.headers.update({
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            })
    
    def search_repositories(self, query: str, sort: str = "stars", order: str = "desc", per_page: int = 30) -> dict:
        """Search for repositories."""
        url = f"{self.BASE_URL}/search/repositories"
        params = {
            'q': query,
            'sort': sort,
            'order': order,
            'per_page': min(per_page, 100)
        }
        try:
            return self._request('GET', url, params=params)
        except Exception as e:
            logger.error(f"GitHub repo search failed: {e}")
            return {}
    
    def search_code(self, query: str, per_page: int = 30) -> dict:
        """Search code across repositories."""
        url = f"{self.BASE_URL}/search/code"
        params = {
            'q': query,
            'per_page': min(per_page, 100)
        }
        try:
            return self._request('GET', url, params=params)
        except Exception as e:
            logger.error(f"GitHub code search failed: {e}")
            return {}
    
    def search_issues(self, query: str, per_page: int = 30) -> dict:
        """Search issues across repositories."""
        url = f"{self.BASE_URL}/search/issues"
        params = {
            'q': query,
            'per_page': min(per_page, 100)
        }
        try:
            return self._request('GET', url, params=params)
        except Exception as e:
            logger.error(f"GitHub issue search failed: {e}")
            return {}
    
    def get_repository(self, owner: str, repo: str) -> dict:
        """Get repository details."""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"GitHub repo details failed for {owner}/{repo}: {e}")
            return {}
    
    def get_repository_contents(self, owner: str, repo: str, path: str = "") -> list:
        """Get contents of a repository directory."""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"GitHub repo contents failed: {e}")
            return []
    
    def get_user(self, username: str) -> dict:
        """Get user profile information."""
        url = f"{self.BASE_URL}/users/{username}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"GitHub user lookup failed for {username}: {e}")
            return {}
    
    def get_organization(self, org: str) -> dict:
        """Get organization information."""
        url = f"{self.BASE_URL}/orgs/{org}"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.error(f"GitHub org lookup failed for {org}: {e}")
            return {}
    
    def get_rate_limit(self) -> dict:
        """Get rate limit status."""
        url = f"{self.BASE_URL}/rate_limit"
        try:
            return self._request('GET', url)
        except Exception as e:
            logger.warning(f"Could not check GitHub rate limit: {e}")
            return {}


# ========================
# Output Formatters
# ========================

class OutputFormatter:
    """Formats output for different targets."""
    
    @staticmethod
    def format_shodan_ip_result(data: dict, target: str) -> str:
        """Format Shodan IP result."""
        if not data:
            return f"{Colors.YELLOW}[INFO]{Colors.ENDC} No data found for {target}"
        
        lines = [f"{Colors.CYAN}=== Shodan Results for {target} ==={Colors.ENDC}"]
        
        # Basic info
        ip = data.get('ip_str', 'N/A')
        country = data.get('country_name', 'N/A')
        city = data.get('city', 'N/A')
        org = data.get('org', 'N/A')
        asn = data.get('asn', 'N/A')
        
        lines.append(f"{Colors.BOLD}IP:{Colors.ENDC} {ip}")
        lines.append(f"{Colors.BOLD}Location:{Colors.ENDC} {city}, {country}")
        lines.append(f"{Colors.BOLD}Organization:{Colors.ENDC} {org}")
        lines.append(f"{Colors.BOLD}ASN:{Colors.ENDC} {asn}")
        
        # Open ports
        ports = data.get('ports', [])
        if ports:
            lines.append(f"\n{Colors.BOLD}Open Ports:{Colors.ENDC}")
            for port_info in data.get('data', []):
                port = port_info.get('port')
                service = port_info.get('service', 'Unknown')
                banner = port_info.get('data', '')[:100]
                lines.append(f"  {Colors.GREEN}{port}/{service}{Colors.ENDC} - {banner}")
        
        # Vulnerabilities
        vulns = data.get('vulns', [])
        if vulns:
            lines.append(f"\n{Colors.BOLD}Vulnerabilities:{Colors.ENDC}")
            for vuln in vulns:
                lines.append(f"  {Colors.RED}{vuln}{Colors.ENDC}")
        
        # Hostnames
        hostnames = data.get('hostnames', [])
        if hostnames:
            lines.append(f"\n{Colors.BOLD}Hostnames:{Colors.ENDC}")
            for hostname in hostnames:
                lines.append(f"  {Colors.BLUE}{hostname}{Colors.ENDC}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_censys_host_result(data: dict, target: str) -> str:
        """Format Censys host result."""
        if not data:
            return f"{Colors.YELLOW}[INFO]{Colors.ENDC} No data found for {target}"
        
        lines = [f"{Colors.CYAN}=== Censys Results for {target} ==={Colors.ENDC}"]
        
        ip = data.get('ip', 'N/A')
        status = data.get('status', 'N/A')
        
        lines.append(f"{Colors.BOLD}IP:{Colors.ENDC} {ip}")
        lines.append(f"{Colors.BOLD}Status:{Colors.ENDC} {status}")
        
        # Location
        location = data.get('last_parsed_response', {}).get('location', {})
        country = location.get('country', 'N/A')
        city = location.get('city', 'N/A')
        lines.append(f"{Colors.BOLD}Location:{Colors.ENDC} {city}, {country}")
        
        # Services
        services = data.get('last_parsed_response', {}).get('services', [])
        if services:
            lines.append(f"\n{Colors.BOLD}Services:{Colors.ENDC}")
            for service in services[:10]:  # Limit to first 10
                port = service.get('port', 'N/A')
                product = service.get('product', 'N/A')
                version = service.get('version', '')
                lines.append(f"  {Colors.GREEN}{port}/{service.get('transport', 'tcp')}{Colors.ENDC} - {product} {version}")
        
        # Certificates
        certs = data.get('last_parsed_response', {}).get('certificates', [])
        if certs:
            lines.append(f"\n{Colors.BOLD}Certificates:{Colors.ENDC}")
            for cert in certs[:5]:  # Limit to first 5
                subject = cert.get('subject_dn', 'N/A')
                issuer = cert.get('issuer_cn', 'N/A')
                lines.append(f"  {Colors.BLUE}Subject:{Colors.ENDC} {subject[:80]}")
                lines.append(f"  {Colors.BLUE}Issuer:{Colors.ENDC} {issuer}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_virustotal_ip_result(data: dict, target: str) -> str:
        """Format VirusTotal IP result."""
        if not data:
            return f"{Colors.YELLOW}[INFO]{Colors.ENDC} No data found for {target}"
        
        lines = [f"{Colors.CYAN}=== VirusTotal Results for {target} ==={Colors.ENDC}"]
        
        attributes = data.get('data', {}).get('attributes', {})
        
        # Reputation
        reputation = attributes.get('reputation', 0)
        lines.append(f"{Colors.BOLD}Reputation:{Colors.ENDC} {reputation}")
        
        # Last analysis stats
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        if last_analysis_stats:
            lines.append(f"\n{Colors.BOLD}Analysis Stats:{Colors.ENDC}")
            lines.append(f"  {Colors.GREEN}Harmless:{Colors.ENDC} {last_analysis_stats.get('harmless', 0)}")
            lines.append(f"  {Colors.YELLOW}Suspicious:{Colors.ENDC} {last_analysis_stats.get('suspicious', 0)}")
            lines.append(f"  {Colors.RED}Malicious:{Colors.ENDC} {last_analysis_stats.get('malicious', 0)}")
            lines.append(f"  {Colors.BLUE}Undetected:{Colors.ENDC} {last_analysis_stats.get('undetected', 0)}")
        
        # Country
        country = attributes.get('country', 'N/A')
        lines.append(f"\n{Colors.BOLD}Country:{Colors.ENDC} {country}")
        
        # ASN
        asn = attributes.get('asn', 'N/A')
        lines.append(f"{Colors.BOLD}ASN:{Colors.ENDC} {asn}")
        
        # Tags
        tags = attributes.get('tags', [])
        if tags:
            lines.append(f"\n{Colors.BOLD}Tags:{Colors.ENDC}")
            for tag in tags[:10]:
                lines.append(f"  {Colors.CYAN}{tag}{Colors.ENDC}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_github_repo_result(data: dict, target: str) -> str:
        """Format GitHub repository result."""
        if not data:
            return f"{Colors.YELLOW}[INFO]{Colors.ENDC} No data found for {target}"
        
        lines = [f"{Colors.CYAN}=== GitHub Repository Results for {target} ==={Colors.ENDC}"]
        
        name = data.get('full_name', 'N/A')
        description = data.get('description', 'N/A')
        stars = data.get('stargazers_count', 0)
        forks = data.get('forks_count', 0)
        language = data.get('language', 'N/A')
        created = data.get('created_at', 'N/A')
        updated = data.get('updated_at', 'N/A')
        license_info = data.get('license', {}).get('spdx_id', 'N/A') if data.get('license') else 'N/A'
        
        lines.append(f"{Colors.BOLD}Name:{Colors.ENDC} {name}")
        lines.append(f"{Colors.BOLD}Description:{Colors.ENDC} {description}")
        lines.append(f"{Colors.BOLD}Stars:{Colors.ENDC} {stars}")
        lines.append(f"{Colors.BOLD}Forks:{Colors.ENDC} {forks}")
        lines.append(f"{Colors.BOLD}Language:{Colors.ENDC} {language}")
        lines.append(f"{Colors.BOLD}Created:{Colors.ENDC} {created}")
        lines.append(f"{Colors.BOLD}Updated:{Colors.ENDC} {updated}")
        lines.append(f"{Colors.BOLD}License:{Colors.ENDC} {license_info}")
        
        # Topics
        topics = data.get('topics', [])
        if topics:
            lines.append(f"\n{Colors.BOLD}Topics:{Colors.ENDC}")
            for topic in topics:
                lines.append(f"  {Colors.MAGENTA}{topic}{Colors.ENDC}")
        
        return "\n".join(lines)


# ========================
# Main OSINT Orchestrator
# ========================

class PassiveOSINT:
    """Main orchestrator for passive OSINT operations."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.shodan_key = self.config.get('shodan_api_key', os.getenv('SHODAN_API_KEY', ''))
        self.censys_id = self.config.get('censys_api_id', os.getenv('CENSYS_API_ID', ''))
        self.censys_secret = self.config.get('censys_api_secret', os.getenv('CENSYS_API_SECRET', ''))
        self.vt_key = self.config.get('virustotal_api_key', os.getenv('VT_API_KEY', ''))
        self.github_token = self.config.get('github_token', os.getenv('GITHUB_TOKEN', ''))
        
        self.clients = {}
        self.results = {}
        
        # Initialize clients
        if self.shodan_key:
            self.clients['shodan'] = ShodanClient(self.shodan_key)
        if self.censys_id and self.censys_secret:
            self.clients['censys'] = CensysClient(self.censys_id, self.censys_secret)
        if self.vt_key:
            self.clients['vt'] = VirusTotalClient(self.vt_key)
        if self.github_token:
            self.clients['github'] = GitHubClient(self.github_token)
        elif self.config.get('github_public'):
            self.clients['github'] = GitHubClient()
    
    def _get_client(self, name: str) -> Optional[APIClient]:
        """Get client by name."""
        return self.clients.get(name)
    
    def analyze_ip(self, ip: str) -> dict:
        """Analyze an IP address across all available sources."""
        result = {'ip': ip, 'timestamp': datetime.now().isoformat()}
        
        # Shodan
        if 'shodan' in self.clients:
            try:
                shodan_data = self.clients['shodan'].get_host(ip)
                result['shodan'] = shodan_data
                logger.info(f"Shodan analysis completed for {ip}")
            except Exception as e:
                logger.error(f"Shodan analysis failed for {ip}: {e}")
                result['shodan_error'] = str(e)
        
        # Censys
        if 'censys' in self.clients:
            try:
                censys_data = self.clients['censys'].get_host_details(ip)
                result['censys'] = censys_data
                logger.info(f"Censys analysis completed for {ip}")
            except Exception as e:
                logger.error(f"Censys analysis failed for {ip}: {e}")
                result['censys_error'] = str(e)
        
        # VirusTotal
        if 'vt' in self.clients:
            try:
                vt_data = self.clients['vt'].get_ip_report(ip)
                result['virustotal'] = vt_data
                logger.info(f"VirusTotal analysis completed for {ip}")
            except Exception as e:
                logger.error(f"VirusTotal analysis failed for {ip}: {e}")
                result['vt_error'] = str(e)
        
        self.results[ip] = result
        return result
    
    def analyze_domain(self, domain: str) -> dict:
        """Analyze a domain across all available sources."""
        result = {'domain': domain, 'timestamp': datetime.now().isoformat()}
        
        # Shodan
        if 'shodan' in self.clients:
            try:
                shodan_data = self.clients['shodan'].search_domain(domain)
                result['shodan'] = shodan_data
                logger.info(f"Shodan domain analysis completed for {domain}")
            except Exception as e:
                logger.error(f"Shodan domain analysis failed for {domain}: {e}")
                result['shodan_error'] = str(e)
        
        # VirusTotal
        if 'vt' in self.clients:
            try:
                vt_data = self.clients['vt'].get_domain_report(domain)
                result['virustotal'] = vt_data
                logger.info(f"VirusTotal domain analysis completed for {domain}")
            except Exception as e:
                logger.error(f"VirusTotal domain analysis failed for {domain}: {e}")
                result['vt_error'] = str(e)
        
        # GitHub
        if 'github' in self.clients:
            try:
                # Search for repos with domain name
                search_data = self.clients['github'].search_repositories(domain)
                result['github_search'] = search_data
                logger.info(f"GitHub search completed for {domain}")
            except Exception as e:
                logger.error(f"GitHub search failed for {domain}: {e}")
                result['github_error'] = str(e)
        
        self.results[domain] = result
        return result
    
    def analyze_url(self, url: str) -> dict:
        """Analyze a URL using VirusTotal."""
        result = {'url': url, 'timestamp': datetime.now().isoformat()}
        
        if 'vt' in self.clients:
            try:
                vt_data = self.clients['vt'].analyze_url(url)
                result['virustotal'] = vt_data
                logger.info(f"VirusTotal URL analysis completed for {url}")
            except Exception as e:
                logger.error(f"VirusTotal URL analysis failed for {url}: {e}")
                result['vt_error'] = str(e)
        
        self.results[url] = result
        return result
    
    def search_github(self, query: str, search_type: str = "code") -> dict:
        """Search GitHub based on type."""
        result = {'query': query, 'type': search_type, 'timestamp': datetime.now().isoformat()}
        
        if 'github' in self.clients:
            try:
                if search_type == "repositories":
                    data = self.clients['github'].search_repositories(query)
                elif search_type == "code":
                    data = self.clients['github'].search_code(query)
                elif search_type == "issues":
                    data = self.clients['github'].search_issues(query)
                else:
                    data = {"error": f"Unknown search type: {search_type}"}
                
                result['github'] = data
                logger.info(f"GitHub {search_type} search completed for '{query}'")
            except Exception as e:
                logger.error(f"GitHub search failed: {e}")
                result['github_error'] = str(e)
        
        self.results[f"github_{search_type}_{query}"] = result
        return result
    
    def get_all_results(self) -> dict:
        """Get all accumulated results."""
        return self.results
    
    def export_results(self, filename: str = "osint_results.json") -> str:
        """Export results to JSON file."""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            logger.info(f"Results exported to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return ""
    
    def cleanup(self):
        """Clean up resources."""
        for client in self.clients.values():
            client.close()
        logger.info("All API connections closed")


# ========================
# CLI Interface
# ========================

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Passive OSINT Tool - Automated Shodan, Censys, VirusTotal & GitHub API Scraping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze an IP address
  python passive_osint.py ip 192.168.1.1
  
  # Analyze a domain
  python passive_osint.py domain example.com
  
  # Analyze a URL
  python passive_osint.py url https://example.com
  
  # Search GitHub
  python passive_osint.py github-search "password site:github.com" --type code
  
  # Use configuration file
  python passive_osint.py ip 1.2.3.4 --config config.json
        """
    )
    
    parser.add_argument('action', choices=['ip', 'domain', 'url', 'github-search'],
                       help='Action to perform')
    parser.add_argument('target', help='Target to analyze (IP, domain, URL, or search query)')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress non-essential output')
    parser.add_argument('--github-type', choices=['repositories', 'code', 'issues'],
                       default='code', help='GitHub search type (default: code)')
    
    return parser.parse_args()


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return {}


def display_results(results: dict, target: str, quiet: bool = False):
    """Display formatted results."""
    if quiet:
        return
    
    print("\n" + "="*60)
    print(f"RESULTS FOR: {target}")
    print("="*60)
    
    for source, data in results.items():
        if isinstance(data, dict):
            if source == 'shodan':
                formatted = OutputFormatter.format_shodan_ip_result(data, target)
                print(formatted)
            elif source == 'censys':
                formatted = OutputFormatter.format_censys_host_result(data, target)
                print(formatted)
            elif source == 'virustotal' or source.startswith('vt_'):
                formatted = OutputFormatter.format_virustotal_ip_result(data, target)
                print(formatted)
            elif source.startswith('github'):
                formatted = OutputFormatter.format_github_repo_result(data, target)
                print(formatted)
            else:
                print(f"\n{Colors.BOLD}{source.upper()} RESULTS:{Colors.ENDC}")
                print(json.dumps(data, indent=2, default=str)[:1000])
        elif isinstance(data, str) and data.startswith('[ERROR]'):
            print(f"{Colors.RED}{data}{Colors.ENDC}")


def main():
    """Main entry point."""
    args = parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    
    # Load config
    config = {}
    if args.config:
        config = load_config(args.config)
    
    # Initialize OSINT tool
    osint_tool = PassiveOSINT(config)
    
    try:
        target = args.target
        
        if args.action == 'ip':
            logger.info(f"Starting IP analysis for {target}")
            results = osint_tool.analyze_ip(target)
            
            if not args.quiet:
                display_results(results, target, args.quiet)
            
            # Export if requested
            if args.output:
                osint_tool.export_results(args.output)
        
        elif args.action == 'domain':
            logger.info(f"Starting domain analysis for {target}")
            results = osint_tool.analyze_domain(target)
            
            if not args.quiet:
                display_results(results, target, args.quiet)
            
            if args.output:
                osint_tool.export_results(args.output)
        
        elif args.action == 'url':
            logger.info(f"Starting URL analysis for {target}")
            results = osint_tool.analyze_url(target)
            
            if not args.quiet:
                display_results(results, target, args.quiet)
            
            if args.output:
                osint_tool.export_results(args.output)
        
        elif args.action == 'github-search':
            logger.info(f"Starting GitHub search for '{target}' ({args.github_type})")
            results = osint_tool.search_github(target, args.github_type)
            
            if not args.quiet:
                display_results(results, target, args.quiet)
            
            if args.output:
                osint_tool.export_results(args.output)
        
        else:
            logger.error(f"Unknown action: {args.action}")
            sys.exit(1)
        
        if not args.quiet:
            print("\n" + Colors.GREEN + "[SUCCESS]" + Colors.ENDC + " Analysis complete!")
            if args.output:
                print(f"{Colors.GREEN}[OUTPUT]{Colors.ENDC} Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.ENDC} Interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n{Colors.RED}[ERROR]{Colors.ENDC} {str(e)}")
        sys.exit(1)
    finally:
        osint_tool.cleanup()


if __name__ == "__main__":
    main()
