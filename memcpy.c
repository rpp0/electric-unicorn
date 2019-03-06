#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DATA_LEN 128

uint8_t data[DATA_LEN];
uint8_t buffer[DATA_LEN];

void __attribute__((optimize("-O0"))) stop() {
}

int main(int argc, char* argv[]) {
    memcpy(buffer, data, DATA_LEN);

    stop();
    return 0;
}
