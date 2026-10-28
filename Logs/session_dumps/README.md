# Session Dumps Repository

Direktori ini berisi kumpulan capture packet (PCAP) untuk keperluan testing, analisis jaringan, dan demonstrasi protokol.

## Daftar File

- `tcpdump_session_01.pcap`: Capture sesi TCP umum (HTTP/TLS gabungan).
- `http_get_request.pcap`: Paket tunggal request HTTP GET sederhana.
- `tls_handshake.pcap`: Simulasi handshake TLS 1.3.
- `corrupted_packet.pcap`: Paket dengan checksum/error sengaja dibuat rusak untuk testing parser.

## Metadata

Informasi teknis mengenai setiap file tersedia di `metadata.json`.

## Cara Menggunakan

Gunakan Wireshark, tcpdump, atau tshark untuk membuka file `.pcap`.
