/**
 * Aegis Benchmark 01: Stack Buffer Overflow
 * Target: Unchecked buffer copy via strcpy into fixed stack frame.
 * Flaw: User input exceeds 64-byte buffer, corrupting saved EBP/RIP.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *user_input) {
    char buffer[64];
    // VULNERABILITY: strcpy does not enforce bounds checking.
    // If user_input > 64 bytes, it overwrites the function return address.
    strcpy(buffer, user_input);
    printf("[+] Buffer contents: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload>\n", argv[0]);
        return 1;
    }
    printf("[*] Target ELF loaded. Processing input of size %zu bytes...\n", strlen(argv[1]));
    vulnerable_function(argv[1]);
    printf("[*] Function returned successfully.\n");
    return 0;
}
