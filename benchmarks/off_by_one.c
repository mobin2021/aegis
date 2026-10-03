/**
 * Aegis Benchmark 03: Off-By-One Buffer Boundary Overflow
 * Target: Off-by-one loop condition (<= instead of <) corrupting least-significant byte of saved frame pointer.
 */

#include <stdio.h>
#include <string.h>

#define MAX_ITEMS 16

void parse_item_matrix(const char *input) {
    char matrix[MAX_ITEMS];
    int len = strlen(input);

    // VULNERABILITY: Loop condition <= allows writing past buffer by 1 byte
    for (int i = 0; i <= MAX_ITEMS && i < len; i++) {
        matrix[i] = input[i];
    }
    printf("[+] Parsed %d matrix bytes.\n", len > MAX_ITEMS ? MAX_ITEMS + 1 : len);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <matrix_stream>\n", argv[0]);
        return 1;
    }
    parse_item_matrix(argv[1]);
    return 0;
}
