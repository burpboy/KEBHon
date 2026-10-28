#!/usr/bin/env python3
"""
active_mapper.py - Stealth SYN/FIN/XMAS Port & Service Fingerprinting Engine
Version: 1.0.0
Author: Dwi Joko Purwanto 
Description: A robust, multi-threaded TCP port scanner with stealth capabilities including
SYN scan (half-open), FIN scan, XMAS scan, and service fingerprinting via banner grabbing.
Designed for low-noise reconnaissance with configurable concurrency and error resilience.
"""

import socket
import struct
import time
import sys
import os
import argparse
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import logging
import signal
import errno

# ==============================================================================
# Constants & Configuration
# ==============================================================================

DEFAULT_TIMEOUT = 2.5  # seconds
MAX_THREADS = 50       # max concurrent threads
RETRY_ATTEMPTS = 2     # retries on transient failures
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Well-known ports mapping for service identification
WELL_KNOWN_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    11211: "Memcached", 9200: "Elasticsearch", 1433: "MSSQL",
    5900: "VNC", 2049: "NFS", 139: "NetBIOS", 445: "SMB",
    2222: "SSH-Alt", 8888: "HTTP-Proxy", 9090: "WebAdmin",
}

# TCP Flag definitions
TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
    "NS": 0x100,
}


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class ScanResult:
    """Represents the result of scanning a single port."""
    ip: str
    port: int
    protocol: str
    status: str  # open, closed, filtered, open|filtered, closed|filtered
    service: str = ""
    banner: str = ""
    scan_type: str = ""
    response_flags: str = ""
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "service": self.service,
            "banner": self.banner,
            "scan_type": self.scan_type,
            "response_flags": self.response_flags,
            "latency_ms": round(self.latency_ms, 2),
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        return f"[{self.status.upper():<10}] {self.ip}:{self.port}/{self.protocol} | Service: {self.service or 'N/A'} | Banner: {self.banner[:50] if self.banner else 'None'}"


@dataclass
class ScanConfig:
    """Configuration for a scan job."""
    target: str
    ports: List[int]
    scan_types: List[str] = field(default_factory=lambda: ["syn", "fin", "xmas"])
    timeout: float = DEFAULT_TIMEOUT
    max_threads: int = MAX_THREADS
    verbose: bool = False
    output_file: Optional[str] = None
    exclude_ports: Set[int] = field(default_factory=set)
    include_ports: Optional[Set[int]] = None
    service_fingerprint: bool = True
    banner_grab: bool = True
    retry: bool = True
    log_level: str = "INFO"


# ==============================================================================
# Logger Setup
# ==============================================================================

def setup_logger(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("ActiveMapper")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


# ==============================================================================
# Core Scanner Engine
# ==============================================================================

class PortScanner:
    """
    High-performance TCP port scanner supporting multiple stealth scan types.
    
    Supports:
    - SYN Scan (stealth, half-open)
    - FIN Scan (stealth, sends only FIN flag)
    - XMAS Scan (sends FIN+PSH+URG flags)
    - Connect Scan (full TCP handshake fallback)
    - Service Fingerprinting via banner grabbing
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: List[ScanResult] = []
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self.logger = setup_logger(config.log_level)

        # Validate scan types
        valid_scan_types = {"syn", "fin", "xmas", "connect"}
        for st in config.scan_types:
            if st.lower() not in valid_scan_types:
                raise ValueError(f"Invalid scan type: {st}. Must be one of {valid_scan_types}")

    def _resolve_host(self, host: str) -> str:
        """Resolve hostname to IP address."""
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            try:
                addr_info = socket.getaddrinfo(host, None, socket.AF_INET)[0]
                return addr_info[4][0]
            except socket.gaierror as e:
                raise ConnectionError(f"Could not resolve hostname '{host}': {e}")

    def _get_service_name(self, port: int) -> str:
        """Get well-known service name for a port."""
        if port in WELL_KNOWN_SERVICES:
            return WELL_KNOWN_SERVICES[port]
        return "Unknown"

    def _grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """Attempt to grab service banner from an open port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try to read banner
            banner_data = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner_data += chunk
                    if b"\r\n" in banner_data or b"\n" in banner_data:
                        # Stop after first line or reasonable amount
                        lines = banner_data.split(b"\r\n")
                        if len(lines) > 0:
                            banner_data = lines[0]
                            break
            except socket.timeout:
                pass
            finally:
                sock.close()
            
            # Decode banner
            try:
                return banner_data.decode("utf-8", errors="replace").strip()
            except Exception:
                return banner_data.hex()
                
        except (socket.error, OSError, UnicodeDecodeError):
            return ""

    def _send_tcp_packet(self, ip: str, port: int, flags: int, timeout: float) -> Optional[Tuple[int, float]]:
        """
        Send a raw TCP packet and receive response.
        
        Args:
            ip: Target IP
            port: Target port
            flags: TCP flags to set
            timeout: Socket timeout
            
        Returns:
            Tuple of (flags_received, latency_ms) or None on error
        """
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(timeout)
        
        try:
            # Construct IP header
            version_ihl = 0x45  # IPv4, IHL=5 (20 bytes)
            dscp_ecn = 0
            total_length = 20 + 20  # IP header + TCP header
            identification = 0
            flags_offset = 0x4000  # Don't fragment
            ttl = 64
            protocol = socket.IPPROTO_TCP
            checksum = 0
            src_ip = socket.inet_aton("127.0.0.1")  # Source IP (arbitrary)
            dst_ip = socket.inet_aton(ip)
            
            # Build IP header
            ip_header = struct.pack("!BBHHHBBH4s4s",
                                    version_ihl << 4 | 5,
                                    dscp_ecn,
                                    total_length,
                                    identification,
                                    flags_offset,
                                    ttl,
                                    protocol,
                                    checksum,
                                    src_ip,
                                    dst_ip)
            
            # Calculate IP header checksum
            ip_checksum = self._calculate_checksum(ip_header)
            ip_header = struct.pack("!BBHHHBBH4s4s",
                                    version_ihl << 4 | 5,
                                    dscp_ecn,
                                    total_length,
                                    identification,
                                    flags_offset,
                                    ttl,
                                    protocol,
                                    ip_checksum,
                                    src_ip,
                                    dst_ip)
            
            # Construct TCP header
            src_port = 1024 + (hash(f"{ip}{port}{time.time()}") % 64512)  # Random high port
            seq_num = 0
            ack_num = 0
            data_offset_reserved_flags = (5 << 12)  # Data offset = 5 words, reserved = 0
            window_size = 1024
            tcp_checksum = 0
            urgent_pointer = 0
            
            tcp_header = struct.pack("!HHIIBBHHH",
                                     src_port,
                                     port,
                                     seq_num,
                                     ack_num,
                                     data_offset_reserved_flags,
                                     flags,
                                     window_size,
                                     tcp_checksum,
                                     urgent_pointer)
            
            # Wrap packet
            packet = ip_header + tcp_header
            
            # Send packet
            sock.sendto(packet, (ip, 0))
            
            # Receive response
            try:
                response, addr = sock.recvfrom(1024)
                elapsed = (time.time() - start_time) * 1000
                
                # Parse TCP header from response
                if len(response) >= 40:  # IP header (20) + TCP header (20)
                    tcp_header_response = response[20:40]
                    parsed = struct.unpack("!HHIIBBHHH", tcp_header_response)
                    received_flags = parsed[5]
                    
                    return (received_flags, elapsed)
                    
            except socket.timeout:
                return None
            except socket.error as e:
                if e.errno == errno.ECONNRESET or e.errno == 10054:
                    return (TCP_FLAGS["RST"], 0)
                raise
                
        except socket.timeout:
            return None
        except socket.error as e:
            if e.errno == errno.EPERM or e.errno == 1:
                # Permission denied - likely need root for raw sockets
                return self._fallback_connect_scan(ip, port, timeout)
            raise
        finally:
            sock.close()

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate Internet checksum (RFC 1071)."""
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            checksum &= 0xFFFFFFFF
        
        # Fold 32-bit sum to 16 bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF

    def _fallback_connect_scan(self, ip: str, port: int, timeout: float) -> Optional[Tuple[int, float]]:
        """Fallback to standard connect() when raw sockets fail."""
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            elapsed = (time.time() - start_time) * 1000
            sock.close()
            return (0, elapsed)  # No flags on successful connect
        except socket.timeout:
            return None
        except socket.error:
            return (TCP_FLAGS["RST"], 0)

    def _parse_scan_type(self, scan_type: str) -> int:
        """Convert scan type name to TCP flags."""
        scan_type = scan_type.lower()
        if scan_type == "syn":
            return TCP_FLAGS["SYN"]
        elif scan_type == "fin":
            return TCP_FLAGS["FIN"]
        elif scan_type == "xmas":
            return TCP_FLAGS["FIN"] | TCP_FLAGS["PSH"] | TCP_FLAGS["URG"]
        elif scan_type == "connect":
            return 0
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

    def _interpret_response(self, flags_received: int, scan_type: str) -> str:
        """
        Interpret TCP response flags according to RFC 793 and common implementations.
        
        Returns:
            Status string: 'open', 'closed', 'filtered', etc.
        """
        if flags_received is None:
            return "filtered"
        
        if scan_type == "syn":
            if flags_received & TCP_FLAGS["SYN"]:
                if flags_received & TCP_FLAGS["ACK"]:
                    return "open"
                elif flags_received & TCP_FLAGS["RST"]:
                    return "closed"
                else:
                    return "open|filtered"
            elif flags_received == 0:
                return "filtered"
            else:
                return "filtered"
                
        elif scan_type == "fin":
            if flags_received & TCP_FLAGS["RST"]:
                return "closed"
            elif flags_received == 0:
                return "open"
            else:
                return "open|filtered"
                
        elif scan_type == "xmas":
            if flags_received & TCP_FLAGS["RST"]:
                return "closed"
            elif flags_received == 0:
                return "open"
            else:
                return "open|filtered"
                
        elif scan_type == "connect":
            if flags_received == 0:
                return "open"
            elif flags_received & TCP_FLAGS["RST"]:
                return "closed"
            else:
                return "filtered"
        
        return "filtered"

    def _scan_single_port(self, ip: str, port: int, scan_type: str) -> ScanResult:
        """
        Scan a single port with a specific scan type.
        
        Args:
            ip: Target IP
            port: Port number
            scan_type: Type of scan ('syn', 'fin', 'xmas', 'connect')
            
        Returns:
            ScanResult object with findings
        """
        flags = self._parse_scan_type(scan_type)
        last_exception = None
        
        for attempt in range(1 + (1 if self.config.retry else 0)):
            try:
                result = self._send_tcp_packet(ip, port, flags, self.config.timeout)
                
                if result is None:
                    status = "filtered"
                    latency = 0.0
                else:
                    flags_recv, latency = result
                    status = self._interpret_response(flags_recv, scan_type)
                
                # Determine service
                service = ""
                banner = ""
                
                if status in ("open", "open|filtered"):
                    service = self._get_service_name(port)
                    if self.config.banner_grab and self.config.service_fingerprint:
                        banner = self._grab_banner(ip, port, timeout=min(1.0, self.config.timeout / 2))
                
                return ScanResult(
                    ip=ip,
                    port=port,
                    protocol="tcp",
                    status=status,
                    service=service,
                    banner=banner,
                    scan_type=scan_type,
                    response_flags=f"0x{flags_recv:04X}" if result else "",
                    latency_ms=round(latency, 2),
                )
                
            except socket.timeout:
                last_exception = "Timeout"
                continue
            except socket.error as e:
                last_exception = str(e)
                continue
            except Exception as e:
                last_exception = str(e)
                continue
        
        # All attempts failed
        return ScanResult(
            ip=ip,
            port=port,
            protocol="tcp",
            status="filtered",
            service="",
            banner="",
            scan_type=scan_type,
            response_flags="",
            latency_ms=0.0,
        )

    def _scan_port_with_all_types(self, ip: str, port: int) -> List[ScanResult]:
        """
        Scan a port with all configured scan types and aggregate results.
        
        Args:
            ip: Target IP
            port: Port number
            
        Returns:
            List of ScanResult objects (one per scan type)
        """
        results = []
        
        for scan_type in self.config.scan_types:
            result = self._scan_single_port(ip, port, scan_type)
            results.append(result)
        
        return results

    def _process_target(self, target: str) -> List[ScanResult]:
        """Process a single target (IP or hostname)."""
        resolved_ip = self._resolve_host(target)
        all_results = []
        
        for port in self.config.ports:
            if port in self.config.exclude_ports:
                continue
            if self.config.include_ports and port not in self.config.include_ports:
                continue
                
            port_results = self._scan_port_with_all_types(resolved_ip, port)
            all_results.extend(port_results)
            
            if self.config.verbose:
                for r in port_results:
                    self.logger.debug(str(r))
        
        return all_results

    def run(self) -> List[ScanResult]:
        """
        Execute the full scan across all targets and ports.
        
        Returns:
            List of all ScanResult objects
        """
        self.results = []
        start_time = time.time()
        
        # Prepare scan items
        scan_items = []
        for port in self.config.ports:
            if port in self.config.exclude_ports:
                continue
            if self.config.include_ports and port not in self.config.include_ports:
                continue
            scan_items.append((self.config.target, port))
        
        self.logger.info(f"Starting scan on {self.config.target} - {len(scan_items)} port scans ({self.config.scan_types})")
        
        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            future_to_item = {
                executor.submit(self._process_target, target): item
                for target, port in scan_items
            }
            
            for future in as_completed(future_to_item):
                try:
                    result_list = future.result()
                    with self.lock:
                        self.results.extend(result_list)
                except Exception as e:
                    self.logger.error(f"Error scanning: {e}")
        
        elapsed = time.time() - start_time
        self.logger.info(f"Scan completed in {elapsed:.2f}s - {len(self.results)} total results")
        
        return self.results

    def get_open_ports(self) -> List[Dict]:
        """Get only open ports across all scan types."""
        open_ports = {}
        for result in self.results:
            if result.status in ("open", "open|filtered"):
                key = f"{result.ip}:{result.port}"
                if key not in open_ports:
                    open_ports[key] = result
                else:
                    # Prefer more accurate results
                    if result.service:
                        open_ports[key] = result
        
        return list(open_ports.values())

    def get_summary(self) -> Dict:
        """Generate a summary of scan results."""
        total_ports = len(set(r.port for r in self.results))
        open_ports = sum(1 for r in self.results if r.status in ("open", "open|filtered"))
        closed_ports = sum(1 for r in self.results if r.status == "closed")
        filtered_ports = sum(1 for r in self.results if r.status in ("filtered", "open|filtered", "closed|filtered"))
        
        services_found = set(r.service for r in self.results if r.service)
        
        return {
            "total_ports_scanned": total_ports,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "services_identified": list(services_found),
            "scan_types_used": self.config.scan_types,
            "target": self.config.target,
        }

    def export_results(self, filename: str, format: str = "json") -> str:
        """Export scan results to file."""
        import json
        
        if format == "json":
            data = {
                "scan_config": {
                    "target": self.config.target,
                    "ports": self.config.ports,
                    "scan_types": self.config.scan_types,
                    "timeout": self.config.timeout,
                    "max_threads": self.config.max_threads,
                },
                "summary": self.get_summary(),
                "results": [r.to_dict() for r in self.results],
            }
            
            with open(filename, "w") as f:
                json.dump(data, f, indent=2, default=str)
            
            return filename
        else:
            raise ValueError(f"Unsupported format: {format}")


# ==============================================================================
# CLI Interface
# ==============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stealth SYN/FIN/XMAS Port & Service Fingerprinting Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan specific ports with SYN scan
  python active_mapper.py -t 192.168.1.1 -p 22,80,443 --scan-type syn
  
  # Full stealth scan on a subnet
  python active_mapper.py -t 192.168.1.0/24 -p 1-1024 --verbose
  
  # Scan with all stealth types and banner grabbing
  python active_mapper.py -t example.com -p 80,443,8080 --all-scans --output results.json
        """,
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target IP, hostname, or CIDR range")
    parser.add_argument("-p", "--ports", required=True, help="Comma-separated ports or range (e.g., '22,80,443' or '1-1024')")
    parser.add_argument("--scan-type", nargs="+", choices=["syn", "fin", "xmas", "connect"], 
                        default=["syn"], help="Scan type(s) to use (default: syn)")
    parser.add_argument("--all-scans", action="store_true", help="Use all scan types (syn, fin, xmas, connect)")
    parser.add_argument("-T", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-j", "--threads", type=int, default=MAX_THREADS, help=f"Max concurrent threads (default: {MAX_THREADS})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-error output")
    parser.add_argument("-o", "--output", help="Output file path for results (JSON format)")
    parser.add_argument("--exclude-ports", help="Comma-separated ports to exclude")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    
    return parser.parse_args()


def parse_ports(ports_str: str) -> List[int]:
    """Parse comma-separated ports or ranges into a list of integers."""
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            for p in range(int(start), int(end) + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    args = parse_args()
    
    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error parsing ports: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse exclude ports
    exclude_ports = set()
    if args.exclude_ports:
        try:
            exclude_ports = set(parse_ports(args.exclude_ports))
        except ValueError:
            exclude_ports = set()
    
    # Determine scan types
    scan_types = args.scan_type
    if args.all_scans:
        scan_types = ["syn", "fin", "xmas", "connect"]
    
    # Create configuration
    config = ScanConfig(
        target=args.target,
        ports=ports,
        scan_types=scan_types,
        timeout=args.timeout,
        max_threads=args.threads,
        verbose=args.verbose,
        output_file=args.output,
        exclude_ports=exclude_ports,
        service_fingerprint=True,
        banner_grab=True,
        retry=True,
        log_level=args.log_level,
    )
    
    # Update logger level
    global logger
    logger.handlers.clear()
    logger = setup_logger(args.log_level)
    
    # Run scanner
    scanner = PortScanner(config)
    
    try:
        results = scanner.run()
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        results = scanner.results
    except Exception as e:
        logger.error(f"Fatal error during scan: {e}")
        sys.exit(1)
    
    # Display results
    print("\n" + "=" * 80)
    print("SCAN RESULTS")
    print("=" * 80)
    
    open_results = [r for r in results if r.status in ("open", "open|filtered")]
    other_results = [r for r in results if r.status not in ("open", "open|filtered")]
    
    if open_results:
        print(f"\n🟢 OPEN PORTS ({len(open_results)}):")
        print("-" * 60)
        for r in sorted(open_results, key=lambda x: x.port):
            print(f"  {r}")
    
    if other_results:
        print(f"\n🔴 OTHER STATUS ({len(other_results)}):")
        print("-" * 60)
        for r in sorted(other_results, key=lambda x: x.port):
            print(f"  {r}")
    
    # Summary
    summary = scanner.get_summary()
    print("\n" + "=" * 80)
    print("SCAN SUMMARY")
    print("=" * 80)
    print(f"  Target:          {config.target}")
    print(f"  Ports Scanned:   {summary['total_ports_scanned']}")
    print(f"  Open Ports:      {summary['open_ports']}")
    print(f"  Closed Ports:    {summary['closed_ports']}")
    print(f"  Filtered:        {summary['filtered_ports']}")
    print(f"  Services Found:  {', '.join(summary['services_identified']) if summary['services_identified'] else 'None'}")
    print(f"  Scan Types:      {', '.join(summary['scan_types'])}")
    print("=" * 80)
    
    # Export if requested
    if args.output:
        try:
            scanner.export_results(args.output)
            print(f"\n✅ Results exported to: {args.output}")
        except Exception as e:
            print(f"\n❌ Failed to export results: {e}", file=sys.stderr)
    
    # Exit code based on findings
    if any(r.status in ("open", "open|filtered") for r in results):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
