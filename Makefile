# Compiler: -march=x86_64
# Linker  : -znow,-emain
CC = gcc
SIM_CFLAGS =
SIM_LDFLAGS = -lpthread -lm -lunicorn
CFLAGS = -I../em/wpa_supp_leak/src/ -I../em/wpa_supp_leak/wpa_supplicant -I../em/wpa_supp_leak/src/utils/ -ffunction-sections -Os -fdata-sections -g -mtune=skylake -fno-stack-protector -fno-pie -no-pie -fno-plt -static
#CFLAGS = -I../em/wpa_supp_leak/src/ -I../em/wpa_supp_leak/wpa_supplicant -I../em/wpa_supp_leak/src/utils/ -fno-pie -no-pie
#LDFLAGS = -nostdlib -L/opt/diet/lib-x86_64/ -L../em/wpa_supp_leak/src/crypto/  -Wl,--start-group -lc -lcrypto -lgcc -lm -Wl,--end-group,--gc-sections,-E
LDFLAGS = -L../em/wpa_supp_leak/src/crypto/  -Wl,--start-group -lcrypto -lgcc -lm -Wl,--end-group,--gc-sections,-E,-emain
#LDFLAGS = -L../em/wpa_supp_leak/src/crypto/  -lcrypto
WPA_UTILS_DIR = ../em/wpa_supp_leak/src/utils
WPA_CRYPTO_DIR = ../em/wpa_supp_leak/src/crypto

all: simulate hmac-sha1 simple

simulate: simulate.c
	$(CC) $(SIM_CFLAGS) $(SIM_LDFLAGS) $^ -o $@

simple: simple.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

hmac-sha1: hmac-sha1.c $(WPA_UTILS_DIR)/wpa_debug.c $(WPA_UTILS_DIR)/os_unix.c $(WPA_UTILS_DIR)/common.c $(WPA_CRYPTO_DIR)/crypto_internal.c $(WPA_CRYPTO_DIR)/sha1-prf.c $(WPA_CRYPTO_DIR)/sha1-internal.c $(WPA_CRYPTO_DIR)/sha1.c $(WPA_CRYPTO_DIR)/md5-internal.c
	$(CC) -DCONFIG_CRYPTO_INTERNAL $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	$(RM) simulate hmac-sha1 simple
