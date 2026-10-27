#!/usr/bin/env python3
"""
active_mapper.py - Stealth SYN/FIN/XMAS Port & Service Fingerprinting Engine
Author: Advanced Systems & Security Engineering
Description: High-performance low-level TCP packet crafting and state analysis engine.
"""

import argparse
import os
import socket
import struct
import sys
import time
from typing import Dict, List, Tuple


class TCPChecksum:
    """Utility class for calculating Internet and TCP/IP checksums."""

    @staticmethod
    def calculate(msg: bytes) -> int:
        s = 0
        # Handle odd-length payloads
        for i in range(0, len(msg) - 1, 2):
            s += (msg[i] << 8) + msg[i + 1]
        if len(msg) % 2:
            s += msg[-1] << 8

        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF


class ActiveMapperEngine:
    """Core engine for stealth port scanning and service fingerprinting."""

    # TCP Flag Constants
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    def __init__(
        self, target: str, ports: List[int], scan_type: str, timeout: float
    ):
        self.target = socket.gethostbyname(target)
        self.ports = ports
        self.scan_type = scan_type.upper()
        self.timeout = timeout
        self.results: Dict[int, str] = {}

        if os.geteuid() != 0:
            print(
                "[-] Error: This script requires root/administrator privileges to use raw sockets.",
                file=sys.stderr,
            )
            sys.exit(1)

    def _create_ip_header(
        self, source_ip: str, dest_ip: str, tcp_length: int
    ) -> bytes:
        """Constructs a raw IPv4 header."""
        ihl = 5
        version = 4
        tos = 0
        tot_len = 20 + tcp_length
        ip_id = 54321
        frag_off = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        ip_check = 0
        s_addr = socket.inet_aton(source_ip)
        d_addr = socket.inet_aton(dest_ip)

        ihl_ver = (version << 4) + ihl
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            ihl_ver,
            tos,
            tot_len,
            ip_id,
            frag_off,
            ttl,
            protocol,
            ip_check,
            s_addr,
            d_addr,
        )
        return ip_header

    def _create_tcp_packet(
        self, source_ip: str, dest_ip: str, dest_port: int, flags: int
    ) -> bytes:
        """Constructs a fully formed TCP packet with pseudo-header checksum."""
        source_port = 54321
        seq = 11002233
        ack_seq = 0
        doff = 5
        window = socket.htons(5840)
        urg_ptr = 0

        offset_res_flags = (doff << 12) + flags
        tcp_header_no_sum = struct.pack(
            "!HHLLHHHH",
            source_port,
            dest_port,
            seq,
            ack_seq,
            offset_res_flags,
            window,
            0,
            urg_ptr,
        )

        # Pseudo header for TCP checksum calculation
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header_no_sum)

        psh = struct.pack(
            "!4s4sBBH",
            source_address,
            dest_address,
            placeholder,
            protocol,
            tcp_length,
        )
        psh = psh + tcp_header_no_sum

        tcp_checksum = TCPChecksum.calculate(psh)

        tcp_header = struct.pack(
            "!HHLLHHHH",
            source_port,
            dest_port,
            seq,
            ack_seq,
            offset_res_flags,
            window,
            tcp_checksum,
            urg_ptr,
        )
        ip_header = self._create_ip_header(
            source_ip, dest_ip, len(tcp_header)
        )

        return ip_header + tcp_header

    def _get_local_ip(self, dest_ip: str) -> str:
        """Determines the local source IP address to reach the target."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((dest_ip, 80))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()
        return local_ip

    def scan_port(self, port: int) -> str:
        """Executes the specific scan type on a single port and analyzes the response."""
        try:
            send_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            send_socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_HDRINCL, 1
            )
        except socket.error as e:
            return f"Socket creation error: {e}"

        recv_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )
        recv_socket.settimeout(self.timeout)

        local_ip = self._get_local_ip(self.target)

        # Determine TCP Flags based on Scan Type
        if self.scan_type == "SYN":
            flags = self.SYN
        elif self.scan_type == "FIN":
            flags = self.FIN
        elif self.scan_type == "XMAS":
            flags = self.FIN | self.PSH | self.URG
        else:
            raise ValueError(f"Unsupported scan type: {self.scan_type}")

        packet = self._create_tcp_packet(local_ip, self.target, port, flags)

        try:
            send_socket.sendto(packet, (self.target, 0))

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = recv_socket.recvfrom(65535)
                    if addr[0] != self.target:
                        continue

                    # Parse IP header
                    ip_header_len = (data[0] & 0x0F) * 4
                    tcp_header = data[
                        ip_header_len : ip_header_len + 20
                    ]
                    unpacked_tcp = struct.unpack(
                        "!HHLLHHHH", tcp_header
                    )

                    src_port = unpacked_tcp[0]
                    dst_port = unpacked_tcp[1]
                    tcp_flags = unpacked_tcp[4] & 0x3F

                    if src_port == port:
                        if self.scan_type == "SYN":
                            if tcp_flags & (self.SYN | self.ACK) == (
                                self.SYN | self.ACK
                            ):
                                return "OPEN"
                            elif tcp_flags & self.RST:
                                return "CLOSED"
                        elif self.scan_type in ["FIN", "XMAS"]:
                            if tcp_flags & self.RST:
                                return "CLOSED"
                        break
                except socket.timeout:
                    break

            if self.scan_type == "SYN":
                return "FILTERED"
            else:
                return "OPEN|FILTERED"

        finally:
            send_socket.close()
            recv_socket.close()

    def run(self):
        """Runs the scanning engine across all designated ports."""
        print(f"[*] Starting {self.scan_type} scan on {self.target}...")
        print(f"[*] Target Ports: {self.ports}\n")

        print(f"{'PORT':<10} | {'STATE':<15} | {'SERVICE / ENGINE TAG'}")
        print("-" * 45)

        for port in self.ports:
            state = self.scan_port(port)
            self.results[port] = state
            service_tag = self._infer_service(port, state)
            print(f"{port:<10} | {state:<15} | {service_tag}")

    @staticmethod
    def _infer_service(port: int, state: str) -> String:
        """Basic heuristic service fingerprinting lookup table."""
        known_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Proxy",
        }
        if state == "OPEN" or state == "OPEN|FILTERED":
            return known_ports.get(port, "unknown-service")
        return "closed-filtered"


def parse_ports(port_str: str) -> List[int]:
    """Parses port ranges and individual port inputs."""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(list(set(ports)))


def main():
    parser = argparse.ArgumentParser(
        description="ActiveMapper - Stealth SYN/FIN/XMAS Port & Service Fingerprinting Engine"
    )
    parser.add_argument(
        "-t", "--target", required=True, help="Target IP address or hostname"
    )
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="Ports to scan (e.g., 22,80,443 or 1-1024)",
    )
    parser.add_argument(
        "-s",
        "--scan",
        choices=["SYN", "FIN", "XMAS"],
        default="SYN",
        help="Stealth scan technique (SYN, FIN, XMAS)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Socket response timeout in seconds",
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[-] Invalid port format: {e}", file=sys.stderr)
        sys.exit(1)

    engine = ActiveMapperEngine(args.target, ports, args.scan, args.timeout)
    engine.run()


if __name__ == "__main__":
    main()
