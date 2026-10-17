/*
 * Real-World Vulnerability Case Study: Legacy Auth Parser
 * HARDENED VIA AEGIS 2.0 AUTOMATED MITIGATION PATCH
 * Vulnerability CWE-120: Resolved with bounded snprintf()
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void authenticate_user(const char *input) {
    char token_buffer[64];
    
    // MITIGATED: Bounded snprintf prevents buffer overflow (CWE-120 mitigated)
    snprintf(token_buffer, sizeof(token_buffer), "%s", input);
    
    printf("[+] Processing token: %s\n", token_buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <auth_token>\n", argv[0]);
        return 1;
    }
    
    printf("[*] Starting authentication service...\n");
    authenticate_user(argv[1]);
    printf("[+] Authentication routine completed successfully.\n");
    return 0;
}
