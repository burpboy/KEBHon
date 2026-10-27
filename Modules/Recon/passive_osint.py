import os
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import requests

# Konfigurasi Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("PassiveOSINT")

@dataclass
class OSINTConfig:
    shodan_api_key: Optional[str] = field(default_factory=lambda: os.getenv("SHODAN_API_KEY"))
    censys_api_id: Optional[str] = field(default_factory=lambda: os.getenv("CENSYS_API_ID"))
    censys_api_secret: Optional[str] = field(default_factory=lambda: os.getenv("CENSYS_API_SECRET"))
    virustotal_api_key: Optional[str] = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))

class BaseCollector:
    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self.session = requests.Session()

class ShodanCollector(BaseCollector):
    def __init__(self, api_key: Optional[str], timeout: int = 10) -> None:
        super().__init__(timeout)
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def get_host_info(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "Shodan API key is missing."}
        
        url = f"{self.base_url}/shodan/host/{ip}"
        try:
            response = self.session.get(url, params={"key": self.api_key}, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Shodan API error for IP {ip}: {e}")
            return {"error": str(e)}

class CensysCollector(BaseCollector):
    def __init__(self, api_id: Optional[str], api_secret: Optional[str], timeout: int = 10) -> None:
        super().__init__(timeout)
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = "https://search.censys.io/api/v1"

    def get_host_info(self, ip: str) -> Dict[str, Any]:
        if not self.api_id or not self.api_secret:
            return {"error": "Censys API credentials are missing."}
        
        url = f"{self.base_url}/view/ip/{ip}"
        try:
            response = self.session.get(url, auth=(self.api_id, self.api_secret), timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Censys API error for IP {ip}: {e}")
            return {"error": str(e)}

class VirusTotalCollector(BaseCollector):
    def __init__(self, api_key: Optional[str], timeout: int = 10) -> None:
        super().__init__(timeout)
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "VirusTotal API key is missing."}
        
        url = f"{self.base_url}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error for IP {ip}: {e}")
            return {"error": str(e)}

class GitHubCollector(BaseCollector):
    def __init__(self, token: Optional[str], timeout: int = 10) -> None:
        super().__init__(timeout)
        self.token = token
        self.base_url = "https://api.github.com"

    def search_code(self, query: str) -> Dict[str, Any]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        url = f"{self.base_url}/search/code"
        try:
            response = self.session.get(url, headers=headers, params={"q": query}, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API error for query '{query}': {e}")
            return {"error": str(e)}

class PassiveOSINTOrchestrator:
    def __init__(self, config: Optional[OSINTConfig] = None) -> None:
        self.config = config or OSINTConfig()
        self.shodan = ShodanCollector(self.config.shodan_api_key)
        self.censys = CensysCollector(self.config.censys_api_id, self.config.censys_api_secret)
        self.virustotal = VirusTotalCollector(self.config.virustotal_api_key)
        self.github = GitHubCollector(self.config.github_token)

    def gather_ip_intelligence(self, ip: str) -> Dict[str, Any]:
        logger.info(f"Gathering passive OSINT for IP: {ip}")
        return {
            "shodan": self.shodan.get_host_info(ip),
            "censys": self.censys.get_host_info(ip),
            "virustotal": self.virustotal.get_ip_report(ip)
        }

    def gather_github_intelligence(self, query: str) -> Dict[str, Any]:
        logger.info(f"Searching GitHub code for query: {query}")
        return {
            "github": self.github.search_code(query)
        }

if __name__ == "__main__":
    # Contoh Penggunaan
    # Set environment variables terlebih dahulu atau inisialisasi OSINTConfig secara langsung
    osint_engine = PassiveOSINTOrchestrator()
    
    target_ip = "8.8.8.8"
    ip_results = osint_engine.gather_ip_intelligence(target_ip)
    print("IP Intelligence Results:")
    print(ip_results)

    target_query = "org:example-target password"
    github_results = osint_engine.gather_github_intelligence(target_query)
    print("\nGitHub Intelligence Results:")
    print(github_results)
