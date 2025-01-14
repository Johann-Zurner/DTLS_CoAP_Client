#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C"
{
#endif

#define WOLFSSL_TLS13
#ifdef CONFIG_WOLFSSL_DTLS
#define WOLFSSL_DTLS
#define HAVE_SOCKADDR
#define WOLFSSL_DTLS13
#define WOLFSSL_DTLS_CID
#endif

#define HAVE_TLS_EXTENSIONS
#define HAVE_AEAD
#define HAVE_HKDF
#define HAVE_FFDHE_2048
#define WOLFSSL_SEND_HRR_COOKIE

#define NO_FILESYSTEM

#ifdef CONFIG_WOLFSSL_PSK
#undef NO_PSK
#else
#define NO_PSK
#endif

#define NO_WRITEV
#define WC_RSA_PSS
#define HAVE_AESGCM
#define HAVE_POLY1305
#define HAVE_CURVE25519
//#define HAVE_ED25519
#define WOLFSSL_SHA512
#define HAVE_RPK

#define NO_OLD_TLS

#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES
#define ECC_USER_CURVES
#define ECC_MIN_KEY_SZ 128
#undef NO_ASN_TIME //NO_ASN_TIME enables date checking for certs

    /*Optional Hardening Options against Blinding and Side-Channel attacks - slows down DTLS handshake)*/
//#define TFM_TIMING_RESISTANT
//#define ECC_TIMING_RESISTANT
//#define WC_RSA_BLINDING

// experimental
//#define WOLFSSL_ARMASM

// #define WOLFSSL_NO_RSA
/*
#define WOLFSSL_CUSTOM_CURVES
#define WOLFSSL_RNG
#define WOLFSSL_RAND_GEN
#define HAVE_EXTENDED_MASTER
#define HAVE_SERVER_RENEGOTIATION_INFO
#define WOLFSSL_HAVE_PSA
#define WC_PSA_CRYPTO
*/
#define WOLFSSL_HWCRYPTO
//#define WOLFSSL_CRYPTOCELL
#include <pthread.h>

extern pthread_mutex_t memLock; // Declare memLock as extern
#define WOLFSSL_TRACK_MEMORY
//#define WOLFSSL_TRACK_MEMORY_VERBOSE
//#define WOLFSSL_DEBUG_MEMORY

#ifdef __cplusplus
}
#endif

#endif
