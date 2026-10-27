#!/usr/bin/env python3
"""
raw_socket.py - Custom TCP/IP Raw Packet Crafting
Supports: TCP SYN/ACK/FIN/RST, ICMP Echo Request/Reply

WARNING: For educational & authorized testing only.
Requires root privileges (CAP_NET_RAW on Linux).
"""

import socket
import struct
import sys
import os
import platform
import random
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Checksum utilities
# ---------------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    """Compute 16-bit one's complement checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# ---------------------------------------------------------------------------
# IP header
# ---------------------------------------------------------------------------

class IPHeader:
    """IPv4 header builder/parser."""

    PROTO_TCP = 6
    PROTO_ICMP = 1

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        payload: bytes = b"",
        ttl: int = 64,
        ident: Optional[int] = None,
        tos: int = 0,
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.payload = payload
        self.ttl = ttl
        self.ident = ident if ident is not None else random.randint(0, 0xFFFF)
        self.tos = tos
        self.version = 4
        self.ihl = 5
        self.total_length = self.ihl * 4 + len(payload)

    def build(self) -> bytes:
        src = socket.inet_aton(self.src_ip)
        dst = socket.inet_aton(self.dst_ip)

        # version(4) | ihl(4) | tos(8) | total_len(16) | id(16) |
        # flags(3) | frag(13) | ttl(8) | proto(8) | checksum(16) | src | dst
        ver_ihl = (self.version << 4) | self.ihl
        flags_frag = 0x4000  # DF bit set

        header_wo_cksum = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            self.tos,
            self.total_length,
            self.ident,
            flags_frag,
            self.ttl,
            self.protocol,
            0,  # checksum placeholder
            src,
            dst,
        )

        # IP checksum covers only the header
        chksum = _checksum(header_wo_cksum)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            self.tos,
            self.total_length,
            self.ident,
            flags_frag,
            self.ttl,
            self.protocol,
            chksum,
            src,
            dst,
        )
        return header + self.payload

    @staticmethod
    def parse(packet: bytes) -> dict:
        if len(packet) < 20:
            raise ValueError("Packet too short for IP header")
        (
            ver_ihl,
            tos,
            total_len,
            ident,
            flags_frag,
            ttl,
            proto,
            chksum,
            src,
            dst,
        ) = struct.unpack("!BBHHHBBH4s4s", packet[:20])

        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4
        return {
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "total_length": total_len,
            "ident": ident,
            "flags": flags_frag >> 13,
            "frag_offset": flags_frag & 0x1FFF,
            "ttl": ttl,
            "protocol": proto,
            "checksum": chksum,
            "src_ip": socket.inet_ntoa(src),
            "dst_ip": socket.inet_ntoa(dst),
            "payload": packet[ihl:total_len] if ihl <= len(packet) else b"",
        }


# ---------------------------------------------------------------------------
# TCP header
# ---------------------------------------------------------------------------

class TCPHeader:
    """TCP header builder/parser."""

    # TCP flags
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq: int = 0,
        ack: int = 0,
        flags: int = SYN,
        window: int = 65535,
        payload: bytes = b"",
        src_ip: str = "0.0.0.0",
        dst_ip: str = "0.0.0.0",
        urgent: int = 0,
    ) -> None:
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.payload = payload
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.urgent = urgent
        self.data_offset = 5  # 5 * 4 = 20 bytes, no options

    def _pseudo_header(self) -> bytes:
        return struct.pack(
            "!4s4sBBH",
            socket.inet_aton(self.src_ip),
            socket.inet_aton(self.dst_ip),
            0,
            IPHeader.PROTO_TCP,
            self.data_offset * 4 + len(self.payload),
        )

    def build(self) -> bytes:
        offset_flags = (self.data_offset << 12) | (self.flags & 0x1FF)

        header_wo_cksum = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq & 0xFFFFFFFF,
            self.ack & 0xFFFFFFFF,
            offset_flags,
            self.window,
            0,  # checksum placeholder
            self.urgent,
        )

        pseudo = self._pseudo_header()
        chksum = _checksum(pseudo + header_wo_cksum + self.payload)

        header = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq & 0xFFFFFFFF,
            self.ack & 0xFFFFFFFF,
            offset_flags,
            self.window,
            chksum,
            self.urgent,
        )
        return header + self.payload

    @staticmethod
    def parse(segment: bytes) -> dict:
        if len(segment) < 20:
            raise ValueError("Segment too short for TCP header")
        (
            src_port,
            dst_port,
            seq,
            ack,
            offset_flags,
            window,
            chksum,
            urgent,
        ) = struct.unpack("!HHIIHHHH", segment[:20])

        data_offset = (offset_flags >> 12) * 4
        flags = offset_flags & 0x1FF
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "data_offset": data_offset,
            "flags": flags,
            "window": window,
            "checksum": chksum,
            "urgent": urgent,
            "payload": segment[data_offset:] if data_offset <= len(segment) else b"",
        }


# ---------------------------------------------------------------------------
# ICMP header
# ---------------------------------------------------------------------------

class ICMPHeader:
    """ICMP header builder/parser."""

    ECHO_REPLY = 0
    DEST_UNREACH = 3
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11

    def __init__(
        self,
        icmp_type: int = ECHO_REQUEST,
        code: int = 0,
        ident: int = 0,
        seq: int = 0,
        payload: bytes = b"",
    ) -> None:
        self.icmp_type = icmp_type
        self.code = code
        self.ident = ident
        self.seq = seq
        self.payload = payload

    def build(self) -> bytes:
        header_wo_cksum = struct.pack(
            "!BBHHH",
            self.icmp_type,
            self.code,
            0,  # checksum placeholder
            self.ident,
            self.seq,
        ) + self.payload

        chksum = _checksum(header_wo_cksum)

        return struct.pack(
            "!BBHHH",
            self.icmp_type,
            self.code,
            chksum,
            self.ident,
            self.seq,
        ) + self.payload

    @staticmethod
    def parse(data: bytes) -> dict:
        if len(data) < 8:
            raise ValueError("Data too short for ICMP header")
        icmp_type, code, chksum, ident, seq = struct.unpack("!BBHHH", data[:8])
        return {
            "type": icmp_type,
            "code": code,
            "checksum": chksum,
            "ident": ident,
            "seq": seq,
            "payload": data[8:],
        }


# ---------------------------------------------------------------------------
# Raw socket sender
# ---------------------------------------------------------------------------

class RawSocketSender:
    """Manages a raw socket for crafting and sending packets."""

    def __init__(self, family: int = socket.AF_INET) -> None:
        self.family = family
        self._check_privileges()
        try:
            # IPPROTO_RAW implies IP_HDRINCL on Linux
            self.sock = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError as exc:
            raise PermissionError(
                "Raw socket creation requires root/administrator privileges."
            ) from exc
        except OSError as exc:
            raise OSError(f"Failed to create raw socket: {exc}") from exc

        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.settimeout(3.0)

    @staticmethod
    def _check_privileges() -> None:
        if platform.system() == "Windows":
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    raise PermissionError(
                        "Run this script as Administrator on Windows."
                    )
            except AttributeError:
                pass
        else:
            if os.geteuid() != 0:
                raise PermissionError(
                    "Raw socket crafting requires root privileges (use sudo)."
                )

    def send(self, packet: bytes, dst_ip: str) -> int:
        return self.sock.sendto(packet, (dst_ip, 0))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "RawSocketSender":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Packet builder helpers (high-level API)
# ---------------------------------------------------------------------------

def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int = TCPHeader.SYN,
    seq: int = 0,
    ack: int = 0,
    payload: bytes = b"",
    ttl: int = 64,
) -> bytes:
    """Craft a full IPv4 + TCP packet."""
    tcp = TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        payload=payload,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )
    ip = IPHeader(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=IPHeader.PROTO_TCP,
        payload=tcp.build(),
        ttl=ttl,
    )
    return ip.build()


def build_icmp_packet(
    src_ip: str,
    dst_ip: str,
    icmp_type: int = ICMPHeader.ECHO_REQUEST,
    ident: int = 0,
    seq: int = 0,
    payload: bytes = b"",
    ttl: int = 64,
) -> bytes:
    """Craft a full IPv4 + ICMP packet."""
    icmp = ICMPHeader(
        icmp_type=icmp_type,
        code=0,
        ident=ident,
        seq=seq,
        payload=payload,
    )
    ip = IPHeader(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=IPHeader.PROTO_ICMP,
        payload=icmp.build(),
        ttl=ttl,
    )
    return ip.build()


# ---------------------------------------------------------------------------
# Packet listeners / sniffers
# ---------------------------------------------------------------------------

class PacketSniffer:
    """Simple raw socket listener for TCP/ICMP packets."""

    def __init__(self, protocol: int, timeout: float = 3.0) -> None:
        if platform.system() == "Windows":
            raise OSError("Sniffing is not supported on Windows.")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        except PermissionError as exc:
            raise PermissionError(
                "Sniffing requires root privileges."
            ) from exc
        self.sock.settimeout(timeout)
        self.protocol = protocol

    def recv_packets(self, max_packets: int = 10):
        results = []
        for _ in range(max_packets):
            try:
                raw, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                break
            try:
                ip = IPHeader.parse(raw)
            except ValueError:
                continue
            if ip["protocol"] != self.protocol:
                continue

            entry = dict(ip)
            if self.protocol == IPHeader.PROTO_TCP:
                try:
                    entry["tcp"] = TCPHeader.parse(ip["payload"])
                except ValueError:
                    entry["tcp"] = None
            elif self.protocol == IPHeader.PROTO_ICMP:
                try:
                    entry["icmp"] = ICMPHeader.parse(ip["payload"])
                except ValueError:
                    entry["icmp"] = None
            entry["src_addr"] = addr[0]
            results.append(entry)
        return results

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "PacketSniffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Demo / CLI
# ---------------------------------------------------------------------------

def _flag_to_name(flags: int) -> str:
    names = []
    mapping = [
        (TCPHeader.FIN, "FIN"),
        (TCPHeader.SYN, "SYN"),
        (TCPHeader.RST, "RST"),
        (TCPHeader.PSH, "PSH"),
        (TCPHeader.ACK, "ACK"),
        (TCPHeader.URG, "URG"),
        (TCPHeader.ECE, "ECE"),
        (TCPHeader.CWR, "CWR"),
    ]
    for bit, name in mapping:
        if flags & bit:
            names.append(name)
    return "|".join(names) if names else "NONE"


def _print_banner() -> None:
    print("=" * 60)
    print(" raw_socket.py - TCP/IP Raw Packet Crafting")
    print(" Supports: SYN/ACK/FIN/RST, ICMP Echo")
    print("=" * 60)


def demo(args: list) -> int:
    _print_banner()

    if len(args) < 3:
        print("Usage: python raw_socket.py <src_ip> <dst_ip> [action]")
        print("Actions:")
        print("  syn      Send TCP SYN         (default)")
        print("  ack      Send TCP ACK")
        print("  fin      Send TCP FIN")
        print("  rst      Send TCP RST")
        print("  all      Send SYN, ACK, FIN, RST")
        print("  icmp     Send ICMP Echo Request")
        print("  scan     Listen for TCP responses")
        return 1

    src_ip = args[1]
    dst_ip = args[2]
    action = args[3].lower() if len(args) > 3 else "syn"

    try:
        with RawSocketSender() as sender:
            if action in ("syn", "ack", "fin", "rst", "all"):
                flag_map = {
                    "syn": TCPHeader.SYN,
                    "ack": TCPHeader.ACK,
                    "fin": TCPHeader.FIN,
                    "rst": TCPHeader.RST,
                }
                actions = (
                    ["syn", "ack", "fin", "rst"] if action == "all" else [action]
                )
                for act in actions:
                    sport = random.randint(1024, 65535)
                    dport = 80
                    packet = build_tcp_packet(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=sport,
                        dst_port=dport,
                        flags=flag_map[act],
                        seq=random.randint(0, 0xFFFFFFFF),
                        ack=random.randint(0, 0xFFFFFFFF),
                    )
                    sent = sender.send(packet, dst_ip)
                    print(
                        f"[TCP {act.upper():3}] {src_ip}:{sport} -> "
                        f"{dst_ip}:{dport} | {sent} bytes | flags={_flag_to_name(flag_map[act])}"
                    )
                    time.sleep(0.2)

            elif action == "icmp":
                ident = random.randint(0, 0xFFFF)
                payload = b"raw_socket_ping_" + str(random.randint(0, 9999)).encode()
                packet = build_icmp_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ident=ident,
                    seq=1,
                    payload=payload,
                )
                sent = sender.send(packet, dst_ip)
                print(
                    f"[ICMP ECHO] {src_ip} -> {dst_ip} | {sent} bytes | "
                    f"ident={ident} seq=1"
                )

            elif action == "scan":
                print(f"[*] Listening for TCP packets (timeout 3s)...")
                # reuse sender's socket is not suitable; open sniffer
                # but sender already open — open sniffer after closing sender
                pass

            else:
                print(f"[!] Unknown action: {action}")
                return 1

        # Sniff phase (outside sender context)
        if action in ("syn", "ack", "fin", "rst", "all", "icmp", "scan"):
            print("\n[*] Listening for responses...")
            try:
                with PacketSniffer(socket.IPPROTO_TCP, timeout=2.0) as sniffer:
                    packets = sniffer.recv_packets(max_packets=5)
                    if not packets:
                        print("    (no TCP responses captured)")
                    for p in packets:
                        tcp = p.get("tcp")
                        if tcp:
                            print(
                                f"    TCP {p['src_ip']}:{tcp['src_port']} -> "
                                f"{p['dst_ip']}:{tcp['dst_port']} "
                                f"flags={_flag_to_name(tcp['flags'])}"
                            )
            except (PermissionError, OSError) as exc:
                print(f"    Sniff skipped: {exc}")

            try:
                with PacketSniffer(socket.IPPROTO_ICMP, timeout=2.0) as sniffer:
                    packets = sniffer.recv_packets(max_packets=5)
                    if not packets:
                        print("    (no ICMP responses captured)")
                    for p in packets:
                        icmp = p.get("icmp")
                        if icmp:
                            print(
                                f"    ICMP {p['src_ip']} -> {p['dst_ip']} "
                                f"type={icmp['type']} code={icmp['code']}"
                            )
            except (PermissionError, OSError) as exc:
                print(f"    Sniff skipped: {exc}")

    except PermissionError as exc:
        print(f"[!] Permission error: {exc}")
        return 2
    except OSError as exc:
        print(f"[!] OS error: {exc}")
        return 3
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    print("\n[+] Done.")
    return 0


def main() -> int:
    return demo(sys.argv)


if __name__ == "__main__":
    sys.exit(main())