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
    #define WOLFSSL_STATIC_PSK
#else
    #define NO_PSK
#endif

#define NO_WRITEV
#define WC_RSA_PSS
#define HAVE_AESGCM

#define NO_OLD_TLS

#define HAVE_ECC
#define HAVE_SUPPORTED_CURVES
#define ECC_MIN_KEY_SZ 160
#undef NO_ASN_TIME

/*Optional Hardening Options against Blinding and Side-Channel attacks - slows down DTLS handshake)*/
// #define TFM_TIMING_RESISTANT
// #define ECC_TIMING_RESISTANT
// #define WC_RSA_BLINDING

#ifdef __cplusplus
}
#endif

#endif
