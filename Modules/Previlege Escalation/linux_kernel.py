#!/usr/bin/env python3
"""
linux_kernel.py - Linux Kernel Exploit Suggester & PrivEsc Vector Automator
High-level, robust, and zero-dependency implementation.
"""

import os
import platform
import subprocess
import re
import sys
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

@dataclass
class VulnerabilityRecord:
    cve: str
    name: str
    affected_range: str
    description: str
    risk_level: str
    exploit_ref: str

@dataclass
class PrivEscVector:
    category: str
    details: str
    severity: str

class SystemProfiler:
    """Gathers kernel version, release info, and local misconfigurations safely."""
    
    @staticmethod
    def get_kernel_version() -> str:
        return platform.release()

    @staticmethod
    def get_os_release() -> str:
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=")[1].strip().strip('"')
        except FileNotFoundError:
            pass
        return platform.platform()

    @staticmethod
    def run_command(cmd: List[str]) -> str:
        try:
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=5
            )
            return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            return ""

class KernelVersionParser:
    """Parses semantic kernel versions robustly."""
    
    def __init__(self, version_str: str):
        self.raw_version = version_str
        self.major, self.minor, self.patch = self._parse()

    def _parse(self) -> Tuple[int, int, int]:
        clean_v = re.split(r'[-~]', self.raw_version)[0]
        parts = clean_v.split('.')
        try:
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch_str = parts[2] if len(parts) > 2 else "0"
            patch = int(re.sub(r'[^0-9].*', '', patch_str)) if patch_str else 0
            return major, minor, patch
        except ValueError:
            return 0, 0, 0

    def is_between(self, min_v: Tuple[int, int, int], max_v: Tuple[int, int, int]) -> bool:
        current = (self.major, self.minor, self.patch)
        return min_v <= current <= max_v


class KernelExploitSuggester:
    """Evaluates kernel versions against known historical local privilege escalation vectors."""
    
    def __init__(self, kernel_version: str):
        self.version_parser = KernelVersionParser(kernel_version)
        self.database: List[VulnerabilityRecord] = [
            VulnerabilityRecord(
                cve="CVE-2016-5195",
                name="Dirty COW",
                affected_range="2.6.22 - 4.8.3",
                description="Race condition in memory management (get_user_pages) allowing write access to COW mappings.",
                risk_level="HIGH",
                exploit_ref="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195"
            ),
            VulnerabilityRecord(
                cve="CVE-2022-0847",
                name="Dirty Pipe",
                affected_range="5.8.0 - 5.16.11",
                description="Flaw in pipe buffer manipulation allowing overwriting data in arbitrary read-only files.",
                risk_level="CRITICAL",
                exploit_ref="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847"
            ),
            VulnerabilityRecord(
                cve="CVE-2021-4034",
                name="PwnKit (Polkit pkexec)",
                affected_range="All versions with vulnerable polkit",
                description="Local privilege escalation vulnerability in pkexec polkit utility.",
                risk_level="HIGH",
                exploit_ref="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034"
            ),
            VulnerabilityRecord(
                cve="CVE-2021-3156",
                name="Baron Samedit (Sudo Heap Overflow)",
                affected_range="1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1",
                description="Heap-based buffer overflow in sudo allowing unprivileged users to gain root privileges.",
                risk_level="HIGH",
                exploit_ref="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156"
            )
        ]

    def evaluate(self) -> List[VulnerabilityRecord]:
        matches: List[VulnerabilityRecord] = []
        
        # Dirty COW check
        if self.version_parser.is_between((2, 6, 22), (4, 8, 3)):
            matches.append(self.database[0])
            
        # Dirty Pipe check
        if self.version_parser.is_between((5, 8, 0), (5, 16, 11)):
            matches.append(self.database[1])
            
        # PwnKit and Baron Samedit are generally applicable heuristic candidates if version checks pass or universal
        matches.append(self.database[2])
        matches.append(self.database[3])
        
        return matches


class PrivEscAuditor:
    """Scans local environment for common privilege escalation vectors."""
    
    @staticmethod
    def audit_suid_binaries() -> List[PrivEscVector]:
        vectors = []
        cmd = ["find", "/", "-perm", "-4000", "-type", "f", "2>/dev/null"]
        output = SystemProfiler.run_command(cmd)
        if output:
            suid_files = output.splitlines()
            # Common GTFOBins candidates check
            common_gtfo = {"nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "awk", "sed"}
            for file_path in suid_files:
                binary_name = os.path.basename(file_path)
                if binary_name in common_gtfo:
                    vectors.append(PrivEscVector(
                        category="SUID Binary",
                        details=f"Vulnerable SUID binary found: {file_path} (GTFOBins vector)",
                        severity="HIGH"
                    ))
        return vectors

    @staticmethod
    def audit_sudo_rights() -> List[PrivEscVector]:
        vectors = []
        output = SystemProfiler.run_command(["sudo", "-l"])
        if output and "not allowed" not in output.lower():
            vectors.append(PrivEscVector(
                category="Sudo Rights",
                details=f"Current user has custom sudo privileges:\n{output}",
                severity="CRITICAL"
            ))
        return vectors

    @staticmethod
    def audit_capabilities() -> List[PrivEscVector]:
        vectors = []
        output = SystemProfiler.run_command(["getcap", "-r", "/usr", "2>/dev/null"])
        if output:
            vectors.append(PrivEscVector(
                category="File Capabilities",
                details=f"Discovered binaries with special capabilities:\n{output}",
                severity="MEDIUM"
            ))
        return vectors


def print_banner():
    banner = """
    ╔═════════════════════════════════════════════════════════╗
    ║       Linux Kernel Exploit Suggester & Automator        ║
    ║               Robust & Zero-Dependency                  ║
    ╚═════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    if os.name != "posix":
        print("[-] Error: This tool is designed exclusively for Linux operating systems.", file=sys.stderr)
        sys.exit(1)

    print_banner()

    kernel_ver = SystemProfiler.get_kernel_version()
    os_release = SystemProfiler.get_os_release()

    print(f"[*] Target OS Release   : {os_release}")
    print(f"[*] Target Kernel Version: {kernel_ver}\n")

    print("[+] Analyzing potential kernel vulnerabilities...")
    suggester = KernelExploitSuggester(kernel_ver)
    vulns = suggester.evaluate()

    if vulns:
        print(f"\n[+] Found {len(vulns)} potential exploit vector(s) based on kernel version:\n")
        for idx, v in enumerate(vulns, 1):
            print(f"  {idx}. [{v.risk_level}] {v.cve} - {v.name}")
            print(f"     Affected Range : {v.affected_range}")
            print(f"     Description    : {v.description}")
            print(f"     Reference      : {v.exploit_ref}\n")
    else:
        print("[-] No direct kernel exploit matches found in the heuristic database.\n")

    print("[+] Scanning local system misconfigurations and PrivEsc vectors...")
    auditors = [
        PrivEscAuditor.audit_suid_binaries,
        PrivEscAuditor.audit_sudo_rights,
        PrivEscAuditor.audit_capabilities
    ]

    all_vectors: List[PrivEscVector] = []
    for audit_func in auditors:
        try:
            all_vectors.extend(audit_func())
        except Exception as e:
            print(f"[-] Warning during audit step: {e}", file=sys.stderr)

    if all_vectors:
        print(f"\n[+] Discovered {len(all_vectors)} local PrivEsc vector(s):\n")
        for idx, vec in enumerate(all_vectors, 1):
            print(f"  {idx}. [{vec.severity}] [{vec.category}]")
            print(f"     {vec.details}\n")
    else:
        print("[-] No common local privilege escalation vectors discovered via quick scan.\n")

    print("[*] Analysis completed successfully.")

if __name__ == "__main__":
    main()
