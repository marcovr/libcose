CFLAGS += -DCRYPTO_TC_AES
CRYPTOSRC += $(SRC_DIR)/crypt/tc_aes.c
CFLAGS_CRYPTO += -msse2 -msse -march=native -maes
