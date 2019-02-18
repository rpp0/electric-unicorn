#include <inttypes.h>
#include <string.h>
typedef uint8_t u8;

#define PMK_LEN 32
#define PTK_LEN 64
#define DATA_LEN 76

u8 fake_pmk[PMK_LEN];
u8 fake_ptk[PTK_LEN];
u8 data[DATA_LEN];
u8 fixed_key[] = {0xf8, 0x6b, 0xff, 0xcd, 0xaf, 0x20, 0xd2, 0x44, 0x4f, 0x5d, 0x36, 0x61, 0x26, 0xdb, 0xb7, 0x5e, 0xf2, 0x4a, 0xba, 0x28, 0xe2, 0x18, 0xd3, 0x19, 0xbc, 0xec, 0x7b, 0x87, 0x52, 0x8a, 0x4c, 0x61};
char* label = "Pairwise key expansion";

void stop() {

}

int main(void) {
	for(int i = 0; i < PMK_LEN; i++) {
		fake_pmk[i] = fixed_key[i];
	}

	stop();
	return 0;
}
