/*
 * Real-World Vulnerability Case Study: Legacy Auth Parser
 * Vulnerability: CWE-120 (Buffer Copy without Checking Size of Input)
 * Description: Unbounded strcpy from user input into a fixed-size stack buffer.
 */

#include <stdio.h>
#include <string.h>

void authenticate_user(const char *input) {
    char token_buffer[64];
    
    // VULNERABILITY: Unbounded strcpy into 64-byte stack buffer (CWE-120)
    strcpy(token_buffer, input);
    
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
