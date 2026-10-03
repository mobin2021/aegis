/**
 * Aegis Benchmark 02: Format String Vulnerability
 * Target: Direct user input passed as the format string parameter to printf.
 * Flaw: Format specifiers (%x, %s, %n) permit stack reading and arbitrary write.
 */

#include <stdio.h>
#include <string.h>

void process_client_packet(const char *data) {
    char header_tag[32] = "AUTH_TOKEN_SECRET_9872";
    // VULNERABILITY: User-controlled string passed directly to printf without "%s"
    printf("[*] Raw packet received: ");
    printf(data);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <raw_packet_data>\n", argv[0]);
        return 1;
    }
    process_client_packet(argv[1]);
    return 0;
}
