#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "utils/common.h"
#include "common/wpa_common.h"
#include "crypto/sha1.h"

#define PMK_LEN 32
#define PTK_LEN 64
#define DATA_LEN 76

u8 fake_pmk[PMK_LEN];
u8 fake_ptk[PTK_LEN];
u8 data[DATA_LEN];
u8 fixed_key[] = {0xf8, 0x6b, 0xff, 0xcd, 0xaf, 0x20, 0xd2, 0x44, 0x4f, 0x5d, 0x36, 0x61, 0x26, 0xdb, 0xb7, 0x5e, 0xf2, 0x4a, 0xba, 0x28, 0xe2, 0x18, 0xd3, 0x19, 0xbc, 0xec, 0x7b, 0x87, 0x52, 0x8a, 0x4c, 0x61};
char* label = "Pairwise key expansion";

void __attribute__((optimize("-O0"))) stop() {
}

int main(int argc, char* argv[]) {
    wpa_debug_show_keys = 1;
    u8 buffer[PMK_LEN];

    //memset(fake_ptk, 0x01, PTK_LEN); // Breaks shit
    //memset(data, 0, DATA_LEN);
    //memcpy(fake_pmk, fixed_key, PMK_LEN);

    //wpa_hexdump_key(MSG_INFO, "EU: Executing trace:", fake_pmk, PMK_LEN);
    sha1_prf(fake_pmk, PMK_LEN, label, data, DATA_LEN, fake_ptk, PTK_LEN);
    //memcpy(buffer, fake_pmk, PMK_LEN);
    //wpa_hexdump_key(MSG_INFO, "EU: Derived PTK    :", fake_ptk, PTK_LEN);

    stop();
    return 0;
}
