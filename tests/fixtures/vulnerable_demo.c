#include <stdio.h>
#include <string.h>

void process_request(const char *user_payload) {
    char session_buffer[64];
    /* Unbounded stack buffer copy — CWE-120 */
    strcpy(session_buffer, user_payload);
    /* Uncontrolled format string sink — CWE-134 */
    printf(user_payload);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_request(argv[1]);
    }
    return 0;
}
