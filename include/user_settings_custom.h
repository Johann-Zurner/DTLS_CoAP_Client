#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C"
{
#endif

#define WOLFSSL_TLS13 // enable TLS 1.3 (necessary for DTLS)
#ifdef CONFIG_WOLFSSL_DTLS
#define WOLFSSL_DTLS
#define HAVE_SOCKADDR
#define WOLFSSL_DTLS13 // enable DTLS 1.3
#define WOLFSSL_DTLS_CID
#endif

/*
#define HAVE_ML_KEM
#define WOLFSSL_HAVE_HYBRID
#define WOLFSSL_DILITHIUM_LEVEL2
#define WOLFSSL_DILITHIUM_LEVEL3
#define WOLFSSL_DILITHIUM_LEVEL5
#define HAVE_ML_DSA
*/
#define HAVE_KYBER
#define WOLFSSL_DTLS_CH_FRAG
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHA3
#define WOLFSSL_DTLS_FRAG_CLNT_HELLO

//#define HAVE_DILITHIUM
//#define WOLFSSL_HAVE_ML_DSA
//#define WOLFSSL_WC_DILITHIUM

#define HAVE_TLS_EXTENSIONS // Mandatory for DTLS 1.3
#define HAVE_AEAD           // Required vor DTLS 1.3
#define HAVE_HKDF           // Required vor DTLS 1.3
#define HAVE_FFDHE_2048
#define WOLFSSL_SEND_HRR_COOKIE // Send HelloRetryRequest cookie

#define NO_FILESYSTEM // Enable buffer extensions to load certs

#ifdef CONFIG_WOLFSSL_PSK
#undef NO_PSK // Enable PSK
#else
#define NO_PSK
#endif

#define NO_WRITEV
#define WC_RSA_PSS
#define HAVE_AESGCM // AES-GCM is used in AEAD ciphers
#define HAVE_POLY1305
#define HAVE_CURVE25519
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define HAVE_RPK

#define NO_OLD_TLS

#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES // Required for ECC and x25519
#define ECC_USER_CURVES
#define ECC_MIN_KEY_SZ 128
#undef NO_ASN_TIME // NO_ASN_TIME enables date checking for certs
//#define WC_PSA_CRYPTO
//#define WOLFSSL_HAVE_PSA
//#define WOLFSSL_PSA_ALT



    /*Optional Hardening Options against Blinding and Side-Channel attacks - slows down DTLS handshake)*/
// #define TFM_TIMING_RESISTANT
// #define ECC_TIMING_RESISTANT
// #define WC_RSA_BLINDING

// experimental
// #define WOLFSSL_ARMASM

// #define WOLFSSL_NO_RSA
/*
#define WOLFSSL_CUSTOM_CURVES
#define WOLFSSL_RNG
#define WOLFSSL_RAND_GEN
#define HAVE_EXTENDED_MASTER
#define HAVE_SERVER_RENEGOTIATION_INFO

*/
// #define WOLFSSL_HWCRYPTO
//#define WOLFSSL_CRYPTOCELL
#include <pthread.h>

    extern pthread_mutex_t memLock; // Declare memLock as extern (for memory checks)
#define WOLFSSL_TRACK_MEMORY
    // #define WOLFSSL_TRACK_MEMORY_VERBOSE
    // #define WOLFSSL_DEBUG_MEMORY

#ifdef __cplusplus
}
#endif

#endif
