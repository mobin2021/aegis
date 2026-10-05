/**
 * ==============================================================================
 * Aegis Benchmark Suite: Telemetry Gateway Daemon (v2.4.1)
 * Target: Multi-module network telemetry ingestion service
 * Architecture: x86_64 Linux ELF / POSIX Socket Parser
 * ==============================================================================
 * Security Vulnerability Profile:
 * - Module: session_handler.c / process_telemetry_packet()
 * - Flaw: CWE-121 (Stack-based Buffer Overflow via unbounded packet copy)
 * - Severity: CRITICAL (CVSS 9.8) - Unauthenticated Remote Code Execution
 * ==============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKET_MAGIC 0x54454C4D  // 'TELM'
#define MAX_SESSIONS 16

typedef struct {
    unsigned int magic;
    unsigned short version;
    unsigned short payload_length;
    char session_token[32];
} PacketHeader;

void log_security_event(const char *msg) {
    printf("[GATEWAY-SEC] %s\n", msg);
}

int validate_packet_header(const PacketHeader *hdr) {
    if (hdr->magic != PACKET_MAGIC) {
        log_security_event("Invalid packet magic header. Dropping packet.");
        return -1;
    }
    return 0;
}

/**
 * VULNERABLE FUNCTION:
 * Allocates fixed 64-byte stack buffer for telemetry metrics payload.
 * Copies unconstrained raw packet bytes into local buffer without bounds check.
 */
int process_telemetry_packet(const char *raw_data, int raw_len) {
    char stack_buffer[64];
    PacketHeader header;

    printf("[*] Ingestion pipeline initialized. Processing %d bytes...\n", raw_len);

    // Parse packet metadata
    if (raw_len >= sizeof(PacketHeader)) {
        memcpy(&header, raw_data, sizeof(PacketHeader));
    }

    // VULNERABILITY: strcpy into fixed 64-byte stack frame.
    // Attacker-controlled raw_data corrupts saved RBP and return address (RIP).
    strcpy(stack_buffer, raw_data);

    printf("[+] Telemetry payload buffered successfully at 0x%016lx\n", (unsigned long)stack_buffer);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("===================================================================\n");
    printf(" Aegis Enterprise Target: Industrial Telemetry Ingestion Daemon\n");
    printf(" Listening on 0.0.0.0:9001 (Worker PID: 4892)\n");
    printf("===================================================================\n");

    if (argc < 2) {
        printf("Usage: %s <raw_hex_packet_stream>\n", argv[0]);
        return 1;
    }

    process_telemetry_packet(argv[1], (int)strlen(argv[1]));
    printf("[*] Session terminated cleanly.\n");
    return 0;
}
