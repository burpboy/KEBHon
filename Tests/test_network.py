#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_network.py
Network diagnostic script designed to be bug-free and robust across environments.
Handles missing dependencies, network timeouts, and permission errors gracefully.
"""

import sys
import socket
import urllib.request
import urllib.error
import subprocess
import time
import platform
from datetime import datetime

# Try to import requests, fallback to urllib if not available
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 40)
    print(f" {text}")
    print("=" * 40)


def print_result(status, message):
    """Print a result line with color codes if possible."""
    status_map = {
        "OK": "\033[92mOK\033[0m",
        "FAIL": "\033[91mFAIL\033[0m",
        "WARN": "\033[93mWARN\033[0m",
        "INFO": "\033[96mINFO\033[0m"
    }
    status_str = status_map.get(status, status)
    print(f"[{status_str}] {message}")


def get_local_ip():
    """Get local IP address without connecting to external servers."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def get_public_ip():
    """Get public IP using a reliable service."""
    services = [
        ("https://api.ipify.org", "json"),
        ("https://ifconfig.me/ip", "text")
    ]
    
    for url, fmt in services:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read().decode('utf-8').strip()
                if data:
                    return data
        except Exception:
            continue
    return None

def check_dns_resolution(domain="dns.google"):
    """Check if DNS resolution is working."""
    try:
        start_time = time.time()
        ip = socket.gethostbyname(domain)
        elapsed = (time.time() - start_time) * 1000
        return True, f"{domain} resolves to {ip} ({elapsed:.2f}ms)"
    except socket.gaierror as e:
        return False, f"Failed to resolve {domain}: {e}"
    except Exception as e:
        return False, f"Error resolving {domain}: {e}"

def check_http_connectivity(url="https://www.google.com", timeout=5):
    """Check HTTP connectivity."""
    if HAS_REQUESTS:
        try:
            start_time = time.time()
            response = requests.get(url, timeout=timeout)
            elapsed = (time.time() - start_time) * 1000
            if response.status_code == 200:
                return True, f"HTTP OK ({url}) - Status: {response.status_code} ({elapsed:.2f}ms)"
            else:
                return False, f"HTTP Fail ({url}) - Status: {response.status_code}"
        except requests.exceptions.Timeout:
            return False, f"HTTP Timeout ({url})"
        except requests.exceptions.ConnectionError as e:
            return False, f"HTTP Connection Error ({url}): {str(e)[:50]}"
        except Exception as e:
            return False, f"HTTP Error ({url}): {str(e)[:50]}"
    else:
        # Fallback to urllib
        try:
            start_time = time.time()
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                elapsed = (time.time() - start_time) * 1000
                if response.status == 200:
                    return True, f"HTTP OK ({url}) - Status: {response.status} ({elapsed:.2f}ms)"
                else:
                    return False, f"HTTP Fail ({url}) - Status: {response.status}"
        except urllib.error.URLError as e:
            return False, f"HTTP Error ({url}): {str(e.reason)[:50]}"
        except Exception as e:
            return False, f"HTTP Error ({url}): {str(e)[:50]}"

def check_ping(host="8.8.8.8", count=3, timeout=2):
    """Check ICMP ping connectivity."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), host]
    
    try:
        start_time = time.time()
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(timeout=timeout * count + 5)
        
        if process.returncode == 0:
            elapsed = (time.time() - start_time) * 1000
            # Extract average latency from output if possible
            output = stdout.decode('utf-8')
            # Simple heuristic to find avg latency
            avg_latency = "N/A"
            if "Average" in output or "average" in output:
                parts = output.split()
                for i, part in enumerate(parts):
                    if part.lower() in ["avg", "average"]:
                        if i+1 < len(parts):
                            try:
                                avg_latency = parts[i+1].replace(")", "").replace(",", "")
                            except ValueError:
                                pass
                        break
            
            return True, f"Ping to {host} successful (Avg: {avg_latency}ms)"
        else:
            return False, f"Ping to {host} failed (Return code: {process.returncode})"
            
    except subprocess.TimeoutExpired:
        return False, f"Ping to {host} timed out"
    except FileNotFoundError:
        return False, "Ping command not found (is coreutils installed?)"
    except Exception as e:
        return False, f"Ping error: {str(e)}"

def check_port(host, port, timeout=2):
    """Check if a specific port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True, f"Port {port} on {host} is OPEN"
        else:
            return False, f"Port {port} on {host} is CLOSED/FILTERED"
    except Exception as e:
        return False, f"Error checking port {port}: {str(e)}"

def main():
    print_header("Network Diagnostic Tool")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Platform: {platform.system()} {platform.release()}")
    
    results_summary = []
    
    # 1. Local Network Info
    print_header("Local Network Information")
    local_ip = get_local_ip()
    print_result("INFO", f"Local IP: {local_ip}")
    
    public_ip = get_public_ip()
    if public_ip:
        print_result("OK", f"Public IP: {public_ip}")
    else:
        print_result("WARN", "Could not determine Public IP")
    
    # 2. DNS Resolution
    print_header("DNS Resolution Test")
    domains_to_check = ["google.com", "cloudflare.com", "github.com"]
    dns_ok_count = 0
    for domain in domains_to_check:
        success, msg = check_dns_resolution(domain)
        status = "OK" if success else "FAIL"
        print_result(status, msg)
        if success:
            dns_ok_count += 1
    
    if dns_ok_count == len(domains_to_check):
        results_summary.append(("DNS", True))
    else:
        results_summary.append(("DNS", False))

    # 3. Internet Connectivity (HTTP)
    print_header("Internet Connectivity Test")
    http_urls = ["https://www.google.com", "https://www.cloudflare.com"]
    http_ok_count = 0
    for url in http_urls:
        success, msg = check_http_connectivity(url)
        status = "OK" if success else "FAIL"
        print_result(status, msg)
        if success:
            http_ok_count += 1
            
    if http_ok_count > 0:
        results_summary.append(("HTTP", True))
    else:
        results_summary.append(("HTTP", False))

    # 4. Ping Test
    print_header("Latency/Ping Test")
    ping_targets = ["8.8.8.8", "1.1.1.1"]
    ping_ok_count = 0
    for target in ping_targets:
        success, msg = check_ping(target)
        status = "OK" if success else "FAIL"
        print_result(status, msg)
        if success:
            ping_ok_count += 1
            
    if ping_ok_count > 0:
        results_summary.append(("Ping", True))
    else:
        results_summary.append(("Ping", False))

    # 5. Common Ports Check
    print_header("Common Port Accessibility")
    ports_to_check = [
        ("google.com", 443),
        ("cloudflare.com", 443),
        ("github.com", 443)
    ]
    port_open_count = 0
    for host, port in ports_to_check:
        success, msg = check_port(host, port)
        status = "OK" if success else "FAIL"
        print_result(status, msg)
        if success:
            port_open_count += 1
            
    if port_open_count > 0:
        results_summary.append(("Ports", True))
    else:
        results_summary.append(("Ports", False))

    # Summary
    print_header("Summary")
    all_passed = all([res[1] for res in results_summary])
    for test_name, passed in results_summary:
        status = "PASS" if passed else "FAIL"
        print_result(status, f"{test_name} Test")
    
    if all_passed:
        print_result("OK", "All tests passed! Network looks healthy.")
    else:
        print_result("WARN", "Some tests failed. Check your connection or firewall settings.")

    print("\nDone.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)
