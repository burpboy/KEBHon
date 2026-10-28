#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Kernel Exploit Suggester & PrivEsc Vector Automator
Version: 1.0.0
Author: Dwi Joko Purwanto 
Description: 
    - Auto-detects OS, Kernel Version, Architecture.
    - Fetches live CVEs from NVD API for the detected kernel version.
    - Scans local binaries for known vulnerable versions (DirtyCow, OverlayFS, etc.).
    - Identifies Privilege Escalation vectors (SUID, Capabilities, Cron, Writable paths).
    - Generates a report with actionable advice.
Dependencies: 
    - Python 3.6+
    - requests (for NVD API)
    - subprocess (built-in)
    - os, sys, json, re, datetime (built-in)

Usage:
    python3 linux_kernel.py [--verbose] [--output report.txt] [--api-key <NVD_API_KEY>]
    
Note: 
    Running as root is recommended for full detection of capabilities and SUID files.
"""

import os
import sys
import subprocess
import json
import re
import argparse
import time
from datetime import datetime

# Try to import requests, fallback if not installed
try:
    import requests
    REQUESTS_INSTALLED = True
except ImportError:
    REQUESTS_INSTALLED = False
    print("[!] Warning: 'requests' library not found. Live CVE fetching will be disabled.")
    print("    Install it via: pip install requests")

class LinuxKernelScanner:
    def __init__(self, verbose=False, output_file=None, api_key=None):
        self.verbose = verbose
        self.output_file = output_file
        self.api_key = api_key
        self.results = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_info": {},
            "kernel_cves": [],
            "local_exploits": [],
            "privesc_vectors": [],
            "recommendations": []
        }
        
        # Known vulnerable binary patterns for local scan
        self.local_exploit_signatures = {
            "dirty_cow": {
                "binary": "/bin/gawk",
                "version_pattern": r"3\.",
                "description": "Dirty COW (CVE-2016-5195) - Race condition in the kernel memory subsystem.",
                "check_cmd": "gawk --version"
            },
            "overlayfs": {
                "binary": "/sbin/mount.overlay",
                "version_pattern": r".*",
                "description": "OverlayFS Privilege Escalation (CVE-2015-1328, CVE-2015-1659)",
                "check_cmd": "mount.overlay --version"
            },
            "raw_nikita": {
                "binary": "/usr/bin/raw",
                "description": "Raw driver privilege escalation (CVE-2009-4132)",
                "check_cmd": "which raw"
            }
        }

    def log(self, msg, level="INFO"):
        """Log message to console and optionally to file."""
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_line = f"{timestamp} [{level}] {msg}"
        print(log_line)
        if self.output_file:
            try:
                with open(self.output_file, "a") as f:
                    f.write(log_line + "\n")
            except Exception as e:
                pass # Silently fail file writing

    def run_command(self, cmd, shell=True):
        """Safely execute a command and return stdout, stderr, and return code."""
        try:
            result = subprocess.run(
                cmd, 
                shell=shell, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                timeout=10
            )
            return {
                "stdout": result.stdout.decode('utf-8', errors='ignore').strip(),
                "stderr": result.stderr.decode('utf-8', errors='ignore').strip(),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Timeout", "returncode": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}

    def detect_system_info(self):
        """Detect OS, Kernel Version, and Architecture."""
        self.log("Detecting system information...")
        
        # Get Kernel Version
        uname_out = self.run_command("uname -r")
        kernel_version = uname_out["stdout"]
        
        # Get OS Name
        os_name = "Unknown"
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release") as f:
                    content = f.read()
                    match = re.search(r'^NAME="?(.+?)"?\s*$', content, re.MULTILINE)
                    if match:
                        os_name = match.group(1)
            except:
                pass
        
        # Get Architecture
        arch_out = self.run_command("uname -m")
        architecture = arch_out["stdout"]
        
        # Get User
        user_out = self.run_command("whoami")
        current_user = user_out["stdout"]
        
        # Get UID
        uid_out = self.run_command("id -u")
        uid = uid_out["stdout"]
        is_root = (uid == "0")
        
        system_info = {
            "os": os_name,
            "kernel_version": kernel_version,
            "architecture": architecture,
            "current_user": current_user,
            "is_root": is_root,
            "uid": uid
        }
        
        self.results["system_info"] = system_info
        self.log(f"System Info: {os_name} | Kernel: {kernel_version} | Arch: {architecture} | User: {current_user} (Root: {is_root})")
        
        return kernel_version

    def fetch_cves_from_nvd(self, kernel_version):
        """Fetch CVEs related to the specific kernel version from NVD API."""
        if not REQUESTS_INSTALLED:
            self.log("Skipping live CVE fetch due to missing 'requests' library.", "WARN")
            return []
            
        if not self.api_key:
            # NVD API has rate limits without key, but we can still try with standard headers
            headers = {}
        else:
            headers = {"X-Api-Key": self.api_key}
            
        self.log(f"Fetching CVEs for kernel {kernel_version} from NVD API...")
        
        cves = []
        try:
            # Search for CVEs containing the kernel version string
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={kernel_version}&resultsPerPage=50"
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("vulnerabilities", []):
                    cve_id = item["cve"]["id"]
                    desc = item["cve"]["descriptions"][0]["value"]
                    # Extract CVSS score if available
                    cvss_score = "N/A"
                    metrics = item["cve"].get("metrics", {})
                    for metric_type, metric_data in metrics.items():
                        if isinstance(metric_data, list) and len(metric_data) > 0:
                            if "cvssData" in metric_data[0]:
                                cvss_score = metric_data[0]["cvssData"]["baseScore"]
                                break
                    
                    cves.append({
                        "id": cve_id,
                        "description": desc[:200] + "...", # Truncate long descriptions
                        "cvss_score": cvss_score
                    })
                self.log(f"Found {len(cves)} potential CVEs from NVD.")
            else:
                self.log(f"NVD API returned status code: {response.status_code}", "WARN")
                
        except Exception as e:
            self.log(f"Error fetching CVEs: {str(e)}", "ERROR")
            
        return cves

    def check_local_exploits(self):
        """Check for local exploits based on binary versions and configurations."""
        self.log("Scanning for local exploit vectors...")
        
        # 1. Check for SUID binaries (common privesc vector)
        suid_binaries = []
        try:
            # Find all SUID files owned by root
            find_cmd = "find / -perm -4000 -type f 2>/dev/null"
            out = self.run_command(find_cmd)
            if out["stdout"]:
                suid_binaries = [b.strip() for b in out["stdout"].split("\n") if b.strip()]
                self.log(f"Found {len(suid_binaries)} SUID binaries.")
                for bin_path in suid_binaries:
                    # Common dangerous SUID binaries
                    if any(dangerous in bin_path.lower() for dangerous in ["nmap", "vim", "vi", "nano", "bash", "sh", "perl", "python", "ruby", "lua", "gcc", "make", "docker", "sudo", "su", "pkexec", "polkit"]):
                        self.results["privesc_vectors"].append({
                            "type": "SUID Binary",
                            "path": bin_path,
                            "risk": "HIGH",
                            "description": f"SUID binary found: {bin_path}. May allow privilege escalation if exploitable."
                        })
        except Exception as e:
            self.log(f"Error scanning SUID: {str(e)}", "ERROR")

        # 2. Check for writable directories in PATH
        path_dirs = os.environ.get("PATH", "").split(":")
        writable_paths = []
        for p in path_dirs:
            if os.path.isdir(p) and os.access(p, os.W_OK):
                writable_paths.append(p)
        
        if writable_paths:
            self.results["privesc_vectors"].append({
                "type": "Writable PATH Directory",
                "paths": writable_paths,
                "risk": "MEDIUM",
                "description": "Writable directories in PATH may allow injection of malicious scripts if cron or sudo uses relative paths."
            })

        # 3. Check for specific kernel vulnerabilities using binary checks
        # Note: This is a heuristic check, not definitive.
        
        # Check Dirty COW (CVE-2016-5195)
        # Vulnerable if gawk is present and kernel version is old enough or specific conditions met
        # We check if gawk exists and its version
        gawk_check = self.run_command("gawk --version 2>/dev/null | head -n 1")
        if gawk_check["returncode"] == 0:
            # Dirty Cow affects many kernels, but specifically exploits race conditions.
            # A simple check: if gawk is present, it's a potential target for the exploit script.
            # We add it as a vector if the kernel is pre-4.8.3 (roughly)
            kernel_ver = self.results["system_info"].get("kernel_version", "")
            # Simple semantic version comparison logic for dirty cow
            if kernel_ver and self.is_kernel_vulnerable(kernel_ver, major_limit=4, minor_limit=8, patch_limit=3):
                self.results["local_exploits"].append({
                    "name": "Dirty COW (CVE-2016-5195)",
                    "binary": "/bin/gawk",
                    "status": "VULNERABLE",
                    "description": "Race condition in the kernel memory subsystem. Exploitable via gawk or other programs with write access to mmap'd files."
                })
            elif gawk_check["stdout"]:
                # Even if kernel is patched, having gawk means you have the tool ready
                self.results["local_exploits"].append({
                    "name": "Dirty COW (CVE-2016-5195) - Tool Present",
                    "binary": "/bin/gawk",
                    "status": "POTENTIAL",
                    "description": "gawk is installed. If the kernel is vulnerable, this binary can be used for exploitation."
                })

        # Check OverlayFS
        mount_overlay_check = self.run_command("mount.overlay --version 2>/dev/null || ls -l /sbin/mount.overlay 2>/dev/null")
        if mount_overlay_check["returncode"] == 0 or os.path.exists("/sbin/mount.overlay"):
            kernel_ver = self.results["system_info"].get("kernel_version", "")
            # OverlayFS vulns were prevalent in 3.x and early 4.x
            if kernel_ver and self.is_kernel_vulnerable(kernel_ver, major_limit=4, minor_limit=4, patch_limit=0):
                self.results["local_exploits"].append({
                    "name": "OverlayFS PrivEsc (CVE-2015-1328)",
                    "binary": "/sbin/mount.overlay",
                    "status": "VULNERABLE",
                    "description": "OverlayFS allows unprivileged users to escalate privileges."
                })
            elif os.path.exists("/sbin/mount.overlay"):
                self.results["local_exploits"].append({
                    "name": "OverlayFS - Binary Present",
                    "binary": "/sbin/mount.overlay",
                    "status": "POTENTIAL",
                    "description": "mount.overlay binary exists. Check kernel version for vulnerability."
                })

        # 4. Check for world-writable config files
        try:
            # Check common config files
            config_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
            for cf in config_files:
                if os.path.exists(cf):
                    stat_info = os.stat(cf)
                    mode = oct(stat_info.st_mode)[-3:]
                    if int(mode[-1]) % 2 == 0: # World writable bit set (last digit even usually means group/other write)
                        # More precise check:
                        if os.access(cf, os.W_OK):
                            self.results["privesc_vectors"].append({
                                "type": "World-Writable Config",
                                "path": cf,
                                "mode": mode,
                                "risk": "HIGH",
                                "description": f"{cf} is world-writable. Could allow password hash theft or sudo config modification."
                            })
        except Exception as e:
            self.log(f"Error checking config permissions: {str(e)}", "ERROR")

        # 5. Check Cron Jobs
        try:
            crontab_out = self.run_command("crontab -l 2>/dev/null")
            if crontab_out["stdout"]:
                lines = crontab_out["stdout"].split("\n")
                for line in lines:
                    if line and not line.startswith("#"):
                        # Extract command
                        parts = line.split()
                        if len(parts) >= 6:
                            cmd = parts[5] # Usually the command
                            if os.path.isfile(cmd) and os.access(cmd, os.X_OK):
                                # Check if the script is writable by current user
                                if os.access(cmd, os.W_OK):
                                    self.results["privesc_vectors"].append({
                                        "type": "Writable Cron Job",
                                        "path": cmd,
                                        "risk": "HIGH",
                                        "description": f"Cron job executes {cmd} which is writable by current user."
                                    })
        except Exception as e:
            self.log(f"Error checking cron: {str(e)}", "ERROR")

        # 6. Check Capabilities (Linux Capability Privesc)
        try:
            cap_out = self.run_command("getcap -r / 2>/dev/null")
            if cap_out["stdout"]:
                lines = cap_out["stdout"].split("\n")
                for line in lines:
                    if line and "cap_" in line:
                        # Parse capability
                        match = re.search(r'(.*?)=(.*)', line)
                        if match:
                            path = match.group(1)
                            caps = match.group(2)
                            if "cap_setuid" in caps or "cap_net_raw" in caps or "cap_dac_override" in caps:
                                self.results["privesc_vectors"].append({
                                    "type": "Linux Capability",
                                    "path": path,
                                    "capabilities": caps,
                                    "risk": "HIGH",
                                    "description": f"Binary {path} has powerful capabilities: {caps}. Can often be exploited for root."
                                })
        except Exception as e:
            self.log(f"Error checking capabilities: {str(e)}", "ERROR")

    def is_kernel_vulnerable(self, kernel_version, major_limit, minor_limit, patch_limit):
        """
        Simple semantic version comparison to check if kernel < limit.
        Returns True if vulnerable (older than limit).
        """
        try:
            # Extract numbers from kernel version (e.g., "4.4.0-21-generic" -> [4, 4, 0])
            parts = re.findall(r'\d+', kernel_version)
            if len(parts) < 3:
                return False
            
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2])
            
            # Compare
            if major < major_limit:
                return True
            if major == major_limit and minor < minor_limit:
                return True
            if major == major_limit and minor == minor_limit and patch < patch_limit:
                return True
                
            return False
        except:
            return False

    def generate_recommendations(self):
        """Generate actionable recommendations based on findings."""
        recs = []
        
        if self.results["system_info"].get("is_root"):
            recs.append("You are already root. No further escalation needed.")
            return recs
            
        if self.results["local_exploits"]:
            recs.append("Exploit Candidates Found:")
            for exp in self.results["local_exploits"]:
                recs.append(f"  - {exp['name']}: {exp['description']}")
                
        if self.results["privesc_vectors"]:
            recs.append("Privilege Escalation Vectors:")
            for vec in self.results["privesc_vectors"]:
                recs.append(f"  - [{vec['risk']}] {vec['type']}: {vec.get('description', vec.get('path', ''))}")
                
        if self.results["kernel_cves"]:
            high_cvss = [cve for cve in self.results["kernel_cves"] if float(cve.get("cvss_score", 0)) >= 7.0]
            if high_cvss:
                recs.append(f"High Severity CVEs ({len(high_cvss)} found):")
                for cve in high_cvss[:5]: # Top 5
                    recs.append(f"  - {cve['id']}: {cve['description']}")
                    
        if not recs:
            recs.append("No critical issues found. System appears relatively secure.")
            
        self.results["recommendations"] = recs

    def run_full_scan(self):
        """Execute the full scan process."""
        self.log("="*50)
        self.log("Starting Linux Kernel Exploit Scan...")
        self.log("="*50)
        
        # Step 1: Detect System Info
        kernel_version = self.detect_system_info()
        
        # Step 2: Fetch Live CVEs
        if kernel_version:
            self.results["kernel_cves"] = self.fetch_cves_from_nvd(kernel_version)
        
        # Step 3: Check Local Exploits and Privesc Vectors
        self.check_local_exploits()
        
        # Step 4: Generate Recommendations
        self.generate_recommendations()
        
        # Step 5: Output Results
        self.log("="*50)
        self.log("Scan Complete.")
        self.log("="*50)
        
        # Print Summary
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {self.results['system_info']['os']} ({self.results['system_info']['kernel_version']})")
        print(f"User: {self.results['system_info']['current_user']} (Root: {self.results['system_info']['is_root']})")
        print(f"Live CVEs Found: {len(self.results['kernel_cves'])}")
        print(f"Local Exploits Detected: {len(self.results['local_exploits'])}")
        print(f"Privesc Vectors Found: {len(self.results['privesc_vectors'])}")
        print("-"*50)
        
        if self.results["recommendations"]:
            print("\nRECOMMENDATIONS:")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"{i}. {rec}")
        
        # Save to JSON if output file specified
        if self.output_file:
            try:
                json_output_path = self.output_file.replace(".txt", ".json")
                with open(json_output_path, "w") as f:
                    json.dump(self.results, f, indent=2)
                print(f"\nDetailed JSON report saved to: {json_output_path}")
            except Exception as e:
                self.log(f"Error saving JSON: {str(e)}", "ERROR")

        return self.results

def main():
    parser = argparse.ArgumentParser(description="Linux Kernel Exploit Suggester & PrivEsc Automator")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--output", type=str, help="Output file for text log (e.g., report.txt)")
    parser.add_argument("--api-key", type=str, help="NVD API Key for higher rate limits")
    
    args = parser.parse_args()
    
    scanner = LinuxKernelScanner(
        verbose=args.verbose,
        output_file=args.output,
        api_key=args.api_key
    )
    
    scanner.run_full_scan()

if __name__ == "__main__":
    main()
