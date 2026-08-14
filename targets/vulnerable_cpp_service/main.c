#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_user_input(const char* input_str) {
    char buffer[64];
    // VULNERABLE FUNCTION (Buffer Overflow): Unbounded strcpy into 64-byte stack buffer
    /* KALPA Security Patch: Bounds-checked strncpy */
    strncpy(buffer, input_str, sizeof(buffer) - 1); buffer[sizeof(buffer) - 1] = \'\0\';
    printf("Processed string: %s\n", buffer);
}

void execute_utility(const char* arg_str) {
    char cmd[128];
    /* KALPA Security Contract Assertion */
    // VULNERABLE FUNCTION (Command Injection): Unsafe sprintf + system()
    sprintf(cmd, "echo %s", arg_str);
    system(cmd);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <mode: 1=buffer, 2=cmd> <input>\n", argv[0]);
        return 1;
    }

    int mode = atoi(argv[1]);
    if (mode == 1) {
        process_user_input(argv[2]);
    } else if (mode == 2) {
        execute_utility(argv[2]);
    }

    return 0;
}
