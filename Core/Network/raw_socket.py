#!/usr/bin/env python3
"""
raw_socket.py - Custom TCP/IP Raw Packet Crafting
Membuat paket mentah untuk:
- TCP Flags: SYN, ACK, FIN, RST
- ICMP Echo Request

Dibutuhkan hak akses root/sudo untuk menjalankan.
"""

import struct
import socket
import random
import sys


def checksum(data: bytes) -> int:
    """Menghitung IP/UDP/TCP pseudo-header checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class TCPPacket:
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int = 0x02, payload: bytes = b''):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.flags = flags  # 2=SYN, 16=ACK, 1=FIN, 4=RST
        self.payload = payload

    def build(self) -> bytes:
        # Source/Dest IPs
        src_ip_raw = socket.inet_aton(self.src_ip)
        dst_ip_raw = socket.inet_aton(self.dst_ip)

        # TCP Header Fields
        seq_num = random.randint(0, 0xFFFFFFFF)
        ack_num = 0
        offset_bits = (5 << 4)  # Data offset = 5 words (20 bytes)
        tcp_flags = self.flags
        window_size = 1024
        urgent_ptr = 0

        # Calculate TCP header length
        tcp_header_len = 20
        if self.payload:
            tcp_header_len += len(self.payload)

        # Construct TCP Header without checksum initially
        tcp_header = struct.pack('!HHIIBBHHH',
                                 self.src_port,
                                 self.dst_port,
                                 seq_num,
                                 ack_num,
                                 offset_bits,
                                 tcp_flags,
                                 window_size,
                                 0,  # Checksum placeholder
                                 urgent_ptr
                                 )

        # Pseudo Header for TCP Checksum
        pseudo_header = struct.pack('!4s4sBB',
                                    src_ip_raw,
                                    dst_ip_raw,
                                    0,
                                    6,  # Protocol TCP
                                    tcp_header_len
                                    )
        
        # Compute Checksum
        check_data = pseudo_header + tcp_header
        tcp_checksum = checksum(check_data)

        # Update TCP Header with correct checksum
        tcp_header_final = struct.pack('!HHIIBBHHH',
                                       self.src_port,
                                       self.dst_port,
                                       seq_num,
                                       ack_num,
                                       offset_bits,
                                       tcp_flags,
                                       window_size,
                                       tcp_checksum,
                                       urgent_ptr
                                       )

        # Construct IP Header
        ip_version_ihl = 0x45  # Version 4, IHL 5
        ip_tos = 0
        ip_total_length = 20 + tcp_header_len
        ip_id = random.randint(0, 0xFFFF)
        ip_flags_frag = 0
        ip_ttl = 64
        ip_protocol = 6  # TCP
        ip_checksum_placeholder = 0

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_version_ihl,
                                ip_tos,
                                ip_total_length,
                                ip_id,
                                ip_flags_frag,
                                ip_ttl,
                                ip_protocol,
                                ip_checksum_placeholder,
                                src_ip_raw,
                                dst_ip_raw
                                )

        # Compute IP Checksum
        ip_check_data = struct.pack('!BBHHHBBH4s4s',
                                    ip_version_ihl,
                                    ip_tos,
                                    ip_total_length,
                                    ip_id,
                                    ip_flags_frag,
                                    ip_ttl,
                                    ip_protocol,
                                    0,
                                    src_ip_raw,
                                    dst_ip_raw
                                    )
        ip_checksum = checksum(ip_check_data)

        # Finalize IP Header
        ip_header_final = struct.pack('!BBHHHBBH4s4s',
                                      ip_version_ihl,
                                      ip_tos,
                                      ip_total_length,
                                      ip_id,
                                      ip_flags_frag,
                                      ip_ttl,
                                      ip_protocol,
                                      ip_checksum,
                                      src_ip_raw,
                                      dst_ip_raw
                                      )

        return ip_header_final + tcp_header_final + self.payload


class ICMPPacket:
    def __init__(self, src_ip: str, dst_ip: str, identifier: int = None, sequence: int = 0, payload: bytes = b'Hello World'):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.identifier = identifier or random.randint(0, 0xFFFF)
        self.sequence = sequence
        self.payload = payload

    def build(self) -> bytes:
        src_ip_raw = socket.inet_aton(self.src_ip)
        dst_ip_raw = socket.inet_aton(self.dst_ip)

        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = self.identifier
        icmp_seq = self.sequence

        # ICMP Header + Payload
        icmp_header = struct.pack('!BBHHH',
                                  icmp_type,
                                  icmp_code,
                                  icmp_checksum,
                                  icmp_id,
                                  icmp_seq
                                  )
        
        # Pseudo Header for ICMP Checksum
        pseudo_header = struct.pack('!4s4sBB',
                                    src_ip_raw,
                                    dst_ip_raw,
                                    0,
                                    1  # Protocol ICMP
                                    )
        
        # Compute ICMP Checksum
        icmp_data = pseudo_header + icmp_header + self.payload
        icmp_checksum_val = checksum(icmp_data)

        # Rebuild ICMP Header with correct checksum
        icmp_header_final = struct.pack('!BBHHH',
                                        icmp_type,
                                        icmp_code,
                                        icmp_checksum_val,
                                        icmp_id,
                                        icmp_seq
                                        )

        # Construct IP Header
        ip_version_ihl = 0x45
        ip_tos = 0
        ip_total_length = 20 + 8 + len(self.payload)
        ip_id = random.randint(0, 0xFFFF)
        ip_flags_frag = 0
        ip_ttl = 64
        ip_protocol = 1  # ICMP
        ip_checksum_placeholder = 0

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_version_ihl,
                                ip_tos,
                                ip_total_length,
                                ip_id,
                                ip_flags_frag,
                                ip_ttl,
                                ip_protocol,
                                ip_checksum_placeholder,
                                src_ip_raw,
                                dst_ip_raw
                                )

        # Compute IP Checksum
        ip_check_data = struct.pack('!BBHHHBBH4s4s',
                                    ip_version_ihl,
                                    ip_tos,
                                    ip_total_length,
                                    ip_id,
                                    ip_flags_frag,
                                    ip_ttl,
                                    ip_protocol,
                                    0,
                                    src_ip_raw,
                                    dst_ip_raw
                                    )
        ip_checksum = checksum(ip_check_data)

        # Finalize IP Header
        ip_header_final = struct.pack('!BBHHHBBH4s4s',
                                      ip_version_ihl,
                                      ip_tos,
                                      ip_total_length,
                                      ip_id,
                                      ip_flags_frag,
                                      ip_ttl,
                                      ip_protocol,
                                      ip_checksum,
                                      src_ip_raw,
                                      dst_ip_raw
                                      )

        return ip_header_final + icmp_header_final + self.payload


def send_packet(sock, packet_bytes: bytes):
    """Mengirim paket raw ke jaringan."""
    sock.sendto(packet_bytes, ("", 0))  # Destination doesn't matter for raw sockets


def main():
    if not sys.platform.startswith("linux"):
        print("[!] Raw sockets are best supported on Linux.")
    
    # Create a raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("[!] Error: Need root privileges to run this script.")
        sys.exit(1)

    target_ip = "192.168.1.1"  # Ganti dengan target Anda
    source_ip = "192.168.1.100"  # Ganti dengan IP lokal Anda

    print(f"[+] Sending packets to {target_ip} from {source_ip}")

    # --- Example 1: TCP SYN Scan ---
    syn_pkt = TCPPacket(source_ip, target_ip, 12345, 80, flags=0x02)
    raw_syn = syn_pkt.build()
    send_packet(sock, raw_syn)
    print(f"[-] Sent TCP SYN to {target_ip}:80")

    # --- Example 2: TCP ACK Probe ---
    ack_pkt = TCPPacket(source_ip, target_ip, 12345, 80, flags=0x10)
    raw_ack = ack_pkt.build()
    send_packet(sock, raw_ack)
    print(f"[-] Sent TCP ACK to {target_ip}:80")

    # --- Example 3: TCP FIN Sweep ---
    fin_pkt = TCPPacket(source_ip, target_ip, 12345, 80, flags=0x01)
    raw_fin = fin_pkt.build()
    send_packet(sock, raw_fin)
    print(f"[-] Sent TCP FIN to {target_ip}:80")

    # --- Example 4: TCP RST Reset ---
    rst_pkt = TCPPacket(source_ip, target_ip, 12345, 80, flags=0x04)
    raw_rst = rst_pkt.build()
    send_packet(sock, raw_rst)
    print(f"[-] Sent TCP RST to {target_ip}:80")

    # --- Example 5: ICMP Ping ---
    icmp_pkt = ICMPPacket(source_ip, target_ip)
    raw_icmp = icmp_pkt.build()
    send_packet(sock, raw_icmp)
    print(f"[-] Sent ICMP Echo Request to {target_ip}")

    sock.close()
    print("[+] Done sending packets.")


if __name__ == "__main__":
    main()
