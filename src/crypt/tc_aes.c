#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cose/crypto.h>
#include <cose/crypto/tc_aes.h>

#ifdef ESP_PLATFORM
#include <esp32/aes.h>
typedef esp_aes_context key_schedule_t;
#else
// compile using -msse2;-msse;-march=native;-maes
#include <wmmintrin.h> //for intrinsics for AES-NI
typedef __m128i key_schedule_t[11];
#endif

#define TC_CRYPTO_SUCCESS COSE_OK
#define TC_CRYPTO_FAIL COSE_ERR_CRYPTO

#define TC_ZERO_BYTE 0x00

/* max additional authenticated size in bytes: 2^16 - 2^8 = 65280 */
#define TC_CCM_AAD_MAX_BYTES 0xff00

/* max message size in bytes: 2^(8L) = 2^16 = 65536 */
#define TC_CCM_PAYLOAD_MAX_BYTES 0x10000

#define Nb (4)  /* number of columns (32-bit words) comprising the state */
#define Nk (4)  /* number of 32-bit words comprising the key */
#define TC_AES_BLOCK_SIZE (Nb*Nk)
#define TC_AES_KEY_SIZE (Nb*Nk)

/* struct tc_ccm_mode_struct represents the state of a CCM computation */
typedef struct tc_ccm_mode_struct {
    key_schedule_t *sched; /* AES key schedule */
    uint8_t *nonce; /* nonce required by CCM */
    unsigned int mlen; /* mac length in bytes (parameter t in SP-800 38C) */
} *TCCcmMode_t;


#ifdef ESP_PLATFORM
void aes128_load_key(const uint8_t *enc_key, key_schedule_t *key_schedule) {
    key_schedule->key_bytes = 16;
    memcpy(key_schedule->key, enc_key, 16);
}

void aes128_enc(uint8_t *plainText, uint8_t *cipherText, key_schedule_t key_schedule) {
    esp_internal_aes_encrypt(&key_schedule, plainText, cipherText);
}
#else
//internal stuff

//macros
#define DO_ENC_BLOCK(m,k) \
	do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

//public API
void aes128_load_key(const uint8_t *enc_key, key_schedule_t *key_schedule){
    (*key_schedule)[0] = _mm_loadu_si128((const __m128i*) enc_key);
    (*key_schedule)[1]  = AES_128_key_exp((*key_schedule)[0], 0x01);
    (*key_schedule)[2]  = AES_128_key_exp((*key_schedule)[1], 0x02);
    (*key_schedule)[3]  = AES_128_key_exp((*key_schedule)[2], 0x04);
    (*key_schedule)[4]  = AES_128_key_exp((*key_schedule)[3], 0x08);
    (*key_schedule)[5]  = AES_128_key_exp((*key_schedule)[4], 0x10);
    (*key_schedule)[6]  = AES_128_key_exp((*key_schedule)[5], 0x20);
    (*key_schedule)[7]  = AES_128_key_exp((*key_schedule)[6], 0x40);
    (*key_schedule)[8]  = AES_128_key_exp((*key_schedule)[7], 0x80);
    (*key_schedule)[9]  = AES_128_key_exp((*key_schedule)[8], 0x1B);
    (*key_schedule)[10] = AES_128_key_exp((*key_schedule)[9], 0x36);
}

void aes128_enc(uint8_t *plainText, uint8_t *cipherText, __m128i *key_schedule){
    __m128i m = _mm_loadu_si128((__m128i *) plainText);

    DO_ENC_BLOCK(m,key_schedule);

    _mm_storeu_si128((__m128i *) cipherText, m);
}
#endif



static int tc_ccm_config(TCCcmMode_t c, key_schedule_t *sched, uint8_t *nonce,
                         unsigned int nlen, unsigned int mlen)
{

    /* input sanity check: */
    if (c == (TCCcmMode_t) 0 ||
        sched == (key_schedule_t *) 0 ||
        nonce == (uint8_t *) 0) {
        return TC_CRYPTO_FAIL;
    } else if (nlen != 13) {
        return TC_CRYPTO_FAIL; /* The allowed nonce size is: 13. See documentation.*/
    } else if ((mlen < 4) || (mlen > 16) || (mlen & 1)) {
        return TC_CRYPTO_FAIL; /* The allowed mac sizes are: 4, 6, 8, 10, 12, 14, 16.*/
    }

    c->mlen = mlen;
    c->sched = sched;
    c->nonce = nonce;

    return TC_CRYPTO_SUCCESS;
}

/**
 * Variation of CBC-MAC mode used in CCM.
 */
static void ccm_cbc_mac(uint8_t *T, const uint8_t *data, unsigned int dlen,
                        unsigned int flag, key_schedule_t sched)
{

    unsigned int i;

    if (flag > 0) {
        T[0] ^= (uint8_t)(dlen >> 8);
        T[1] ^= (uint8_t)(dlen);
        dlen += 2; i = 2;
    } else {
        i = 0;
    }

    while (i < dlen) {
        T[i++ % (Nb * Nk)] ^= *data++;
        if (((i % (Nb * Nk)) == 0) || dlen == i) {
            aes128_enc(T, T, sched);
        }
    }
}

/**
 * Variation of CTR mode used in CCM.
 * The CTR mode used by CCM is slightly different than the conventional CTR
 * mode (the counter is increased before encryption, instead of after
 * encryption). Besides, it is assumed that the counter is stored in the last
 * 2 bytes of the nonce.
 */
static int ccm_ctr_mode(uint8_t *out, unsigned int outlen, const uint8_t *in,
                        unsigned int inlen, uint8_t *ctr, key_schedule_t sched)
{

    uint8_t buffer[TC_AES_BLOCK_SIZE];
    uint8_t nonce[TC_AES_BLOCK_SIZE];
    uint16_t block_num;
    unsigned int i;

    /* input sanity check: */
    if (out == (uint8_t *) 0 ||
        in == (uint8_t *) 0 ||
        ctr == (uint8_t *) 0 ||
        (key_schedule_t *) &sched == (key_schedule_t *) 0 ||
        inlen == 0 ||
        outlen == 0 ||
        outlen != inlen) {
        return TC_CRYPTO_FAIL;
    }

    /* copy the counter to the nonce */
    (void) /*_copy(nonce, sizeof(nonce), ctr, sizeof(nonce))*/memcpy(nonce, ctr, sizeof(nonce));

    /* select the last 2 bytes of the nonce to be incremented */
    block_num = (uint16_t) ((nonce[14] << 8)|(nonce[15]));
    for (i = 0; i < inlen; ++i) {
        if ((i % (TC_AES_BLOCK_SIZE)) == 0) {
            block_num++;
            nonce[14] = (uint8_t)(block_num >> 8);
            nonce[15] = (uint8_t)(block_num);
            aes128_enc(nonce, buffer, sched);
        }
        /* update the output */
        *out++ = buffer[i % (TC_AES_BLOCK_SIZE)] ^ *in++;
    }

    /* update the counter */
    ctr[14] = nonce[14]; ctr[15] = nonce[15];

    return TC_CRYPTO_SUCCESS;
}

static int tc_ccm_generation_encryption(uint8_t *out, unsigned int olen,
                                        const uint8_t *associated_data,
                                        unsigned int alen, const uint8_t *payload,
                                        unsigned int plen, TCCcmMode_t c)
{

    /* input sanity check: */
    if ((out == (uint8_t *) 0) ||
        (c == (TCCcmMode_t) 0) ||
        ((plen > 0) && (payload == (uint8_t *) 0)) ||
        ((alen > 0) && (associated_data == (uint8_t *) 0)) ||
        (alen >= TC_CCM_AAD_MAX_BYTES) || /* associated data size unsupported */
        (plen >= TC_CCM_PAYLOAD_MAX_BYTES) || /* payload size unsupported */
        (olen < (plen + c->mlen))) {  /* invalid output buffer size */
        return TC_CRYPTO_FAIL;
    }

    uint8_t b[Nb * Nk];
    uint8_t tag[Nb * Nk];
    unsigned int i;

    /* GENERATING THE AUTHENTICATION TAG: */

    /* formatting the sequence b for authentication: */
    b[0] = ((alen > 0) ? 0x40:0) | (((c->mlen - 2) / 2 << 3)) | (1);
    for (i = 1; i <= 13; ++i) {
        b[i] = c->nonce[i - 1];
    }
    b[14] = (uint8_t)(plen >> 8);
    b[15] = (uint8_t)(plen);

    /* computing the authentication tag using cbc-mac: */
    aes128_enc(b, tag, *c->sched);
    if (alen > 0) {
        ccm_cbc_mac(tag, associated_data, alen, 1, *c->sched);
    }
    if (plen > 0) {
        ccm_cbc_mac(tag, payload, plen, 0, *c->sched);
    }

    /* ENCRYPTION: */

    /* formatting the sequence b for encryption: */
    b[0] = 1; /* q - 1 = 2 - 1 = 1 */
    b[14] = b[15] = TC_ZERO_BYTE;

    /* encrypting payload using ctr mode: */
    ccm_ctr_mode(out, plen, payload, plen, b, *c->sched);

    b[14] = b[15] = TC_ZERO_BYTE; /* restoring initial counter for ctr_mode (0):*/

    /* encrypting b and adding the tag to the output: */
    aes128_enc(b, b, *c->sched);
    out += plen;
    for (i = 0; i < c->mlen; ++i) {
        *out++ = tag[i] ^ b[i];
    }

    return TC_CRYPTO_SUCCESS;
}

static int tc_ccm_decryption_verification(uint8_t *out, unsigned int olen,
                                          const uint8_t *associated_data,
                                          unsigned int alen, const uint8_t *payload,
                                          unsigned int plen, TCCcmMode_t c)
{

    /* input sanity check: */
    if ((out == (uint8_t *) 0) ||
        (c == (TCCcmMode_t) 0) ||
        ((plen > 0) && (payload == (uint8_t *) 0)) ||
        ((alen > 0) && (associated_data == (uint8_t *) 0)) ||
        (alen >= TC_CCM_AAD_MAX_BYTES) || /* associated data size unsupported */
        (plen >= TC_CCM_PAYLOAD_MAX_BYTES) || /* payload size unsupported */
        (olen < plen - c->mlen)) { /* invalid output buffer size */
        return TC_CRYPTO_FAIL;
    }

    uint8_t b[Nb * Nk];
    uint8_t tag[Nb * Nk];
    unsigned int i;

    /* DECRYPTION: */

    /* formatting the sequence b for decryption: */
    b[0] = 1; /* q - 1 = 2 - 1 = 1 */
    for (i = 1; i < 14; ++i) {
        b[i] = c->nonce[i - 1];
    }
    b[14] = b[15] = TC_ZERO_BYTE; /* initial counter value is 0 */

    /* decrypting payload using ctr mode: */
    ccm_ctr_mode(out, plen - c->mlen, payload, plen - c->mlen, b, *c->sched);

    b[14] = b[15] = TC_ZERO_BYTE; /* restoring initial counter value (0) */

    /* encrypting b and restoring the tag from input: */
    aes128_enc(b, b, *c->sched);
    for (i = 0; i < c->mlen; ++i) {
        tag[i] = *(payload + plen - c->mlen + i) ^ b[i];
    }

    /* VERIFYING THE AUTHENTICATION TAG: */

    /* formatting the sequence b for authentication: */
    b[0] = ((alen > 0) ? 0x40:0)|(((c->mlen - 2) / 2 << 3)) | (1);
    for (i = 1; i < 14; ++i) {
        b[i] = c->nonce[i - 1];
    }
    b[14] = (uint8_t)((plen - c->mlen) >> 8);
    b[15] = (uint8_t)(plen - c->mlen);

    /* computing the authentication tag using cbc-mac: */
    aes128_enc(b, b, *c->sched);
    if (alen > 0) {
        ccm_cbc_mac(b, associated_data, alen, 1, *c->sched);
    }
    if (plen > 0) {
        ccm_cbc_mac(b, out, plen - c->mlen, 0, *c->sched);
    }

    /* comparing the received tag and the computed one: */
    if (/*_compare*/memcmp(b, tag, c->mlen) == 0) {
        return TC_CRYPTO_SUCCESS;
    } else {
        /* erase the decrypted buffer in case of mac validation failure: */
        /*_set*/memset(out, 0, plen - c->mlen);
        return TC_CRYPTO_FAIL;
    }
}

COSE_ssize_t cose_crypto_keygen_aesccm(uint8_t *buf, size_t len, cose_algo_t algo)
{
    (void)len;
    (void)buf;
    (void)algo;
    return COSE_ERR_NOTIMPLEMENTED;
}

int cose_crypto_aead_encrypt_aesccm(uint8_t *c,
                                    size_t *clen,
                                    const uint8_t *msg,
                                    size_t msglen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize) {
    if (keysize != COSE_CRYPTO_AEAD_AES128CCM_KEYBYTES) {
        return COSE_ERR_NOTIMPLEMENTED;
    }

    struct tc_ccm_mode_struct tc_c;
    key_schedule_t sched;
    aes128_load_key(k, &sched);

    int result = tc_ccm_config(&tc_c, &sched, (uint8_t *)npub,
            COSE_CRYPTO_AEAD_AES128CCM_NONCEBYTES,
            COSE_CRYPTO_AEAD_AES128CCM_ABYTES);
    if (result != TC_CRYPTO_SUCCESS) {
        return result;
    }
    *clen = msglen + COSE_CRYPTO_AEAD_AES128CCM_ABYTES;
    return tc_ccm_generation_encryption(
            c,
            *clen,
            aad,
            aadlen,
            msg,
            msglen,
            &tc_c
    );
}

int cose_crypto_aead_decrypt_aesccm(uint8_t *msg,
                                    size_t *msglen,
                                    const uint8_t *c,
                                    size_t clen,
                                    const uint8_t *aad,
                                    size_t aadlen,
                                    const uint8_t *npub,
                                    const uint8_t *k,
                                    size_t keysize) {
    if (keysize != COSE_CRYPTO_AEAD_AES128CCM_KEYBYTES) {
        return COSE_ERR_NOTIMPLEMENTED;
    }

    struct tc_ccm_mode_struct tc_c;
    key_schedule_t sched;
    aes128_load_key(k, &sched);

    int result = tc_ccm_config(&tc_c, &sched, (uint8_t *)npub,
            COSE_CRYPTO_AEAD_AES128CCM_NONCEBYTES,
            COSE_CRYPTO_AEAD_AES128CCM_ABYTES);
    if (result != COSE_OK) {
        return result;
    }
    *msglen = clen - COSE_CRYPTO_AEAD_AES128CCM_ABYTES;
    return tc_ccm_decryption_verification(
            msg,
            *msglen,
            aad,
            aadlen,
            c,
            clen,
            &tc_c
    );
}
