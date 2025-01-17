/*
 * File: main.c
 * Purpose: Implements a CoAP client over DTLS using the WolfSSL library.
 *          The client periodically sends CoAP PUT requests to a server
 *          and manages DTLS connection, including Connection ID for session persistence after IP or port change.
 *
 * Author: Johann Zürner
 * Created: January 16, 2025
 * Last Updated: January 16, 2025
 *
 * Description:
 * This program establishes a secure DTLS session with a server and transmits CoAP Confirmable messages
 * containing a simulated temperature value. The program supports DTLS 1.2 and 1.3 with optional
 * Connection ID (CID). It handles IP changes mid-session when CID is enabled.
 * Resets DTLS session when no ACK is received after a CoAP message.
 * The GPIO pins are set to high during specific operations to profile the program
 * with power consumption measurements.
 *
 * Key Features:
 * - Support for DTLS 1.2 and 1.3 with configurable cipher suites and ecc curves.
 * - Optional use of Connection ID for session persistence.
 * - Secure CoAP communication with PSK or certificate-based authentication.
 * - Debugging capabilities for WolfSSL, memory usage, and CoAP message details.
 *
 * Usage:
 * - Configure the `SERVER_IP`, `SERVER_PORT`, and other constants as needed.
 * - Set CID, certificate, and PSK options in the code as needed.
 * - Build and run the program on a Nordic nRF9160 development board or in a Zephyr environment.
 * - Observe logs to track DTLS session establishment, CoAP messages, and debugging details.
 *
 * Dependencies:
 * - WolfSSL library
 *
 * Notes:
 * - Ensure the certificates or PSK are correctly configured for the chosen authentication method.
 * - Ensure the server is running and listening on the specified IP and port.
 * - Ensure server has the correct certificates and PSK for client authentication.
 * - Modify `COAP_INTERVAL` and `COAP_MAX` to control the frequency and count of CoAP messages.
 *
 * License:
 * This code is released under the MIT License. See LICENSE file for details.
 */
#include <stdio.h>
#include <ncs_version.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <wolfssl/ssl.h>

#include <zephyr/drivers/gpio.h>
#include <zephyr/net/coap.h>

pthread_mutex_t memLock = PTHREAD_MUTEX_INITIALIZER;
#include <wolfssl/wolfcrypt/mem_track.h>

/*Include the header file for the socket API */
#include <zephyr/net/socket.h>
/*inluded for CID randomization*/
#include <zephyr/random/random.h>

/*Includes the cert files in hex*/
#include "rootCA1-der.h"
#include "client-cert-der.h"
#include "client-key-der.h"

// #define USE_CID // Comment out to NOT use Connection ID
#define USE_CERTS // Comment out to use Pre Shared Keys instead of Certificate verification (don't forget same on server side)
// #define USE_DTLS_1_3 // Comment out to use DTLS 1.2 instead of 1.3
#define SHOW_WOLFSSL_DEBUG // Comment out to NOT see WolfSSL Debug logs including timestamps
#define MEMORY_DEBUG_SHOW  // Comment out to NOT see memory debug
#define COAP_INTERVAL 6    // Set the time interval between CoAP PUT messages
#define COAP_MAX 20        // Set the maximum number of CoAP messages before DTLS session shuts down

/* These lines are for adding colors to debug output */
#define GREEN "\033[32m"
#define RED "\033[31m"
#define RESET "\033[0m"

#define COAP_MAX_PDU_SIZE 128
#define PSK_IDENTITY "Client_identity"
#define PSK_KEY "\xdd\xbb\xba\x39\xda\xce\x95\xed\x12\x34\x56\x78\x90\xab\xcd\xef"
#define PSK_KEY_LEN 16

#define SERVER_IP "77.23.124.146"
#define SERVER_PORT 2444
#define BUFFER_SIZE 1024

/* Choose the Zephyr log level
 * e.g. LOG_LEVEL_INF will print only your LOG_INF statements
 * LOG_LEVEL_ERR will print LOG_INF and LOG_ERR, etc.)
 */
LOG_MODULE_REGISTER(DTLS_CoAP_Project, LOG_LEVEL_DBG);

static const struct gpio_dt_spec profiler_pin_10 = {
    .port = DEVICE_DT_GET(DT_NODELABEL(gpio0)), // GPIO controller
    .pin = 10,                                  // Pin number 10
    .dt_flags = (uint16_t)GPIO_OUTPUT_INACTIVE  // Initial state (inactive)
};

static const struct gpio_dt_spec profiler_pin_11 = {
    .port = DEVICE_DT_GET(DT_NODELABEL(gpio0)), // GPIO controller
    .pin = 11,                                  // Pin number 11
    .dt_flags = (uint16_t)GPIO_OUTPUT_INACTIVE  // Initial state (inactive)
};

// Used for WolfSSL custom logging to add timestamps to each log output
void CustomLoggingCallback(const int logLevel, const char *const logMessage);

// Verify received CoAP messages, i.e. read type of message (e.g. confirmable) and extract and print Token and Message_ID
void verify_coap_message(uint8_t *receive_buffer, int ret);

// Needed when using PSK
unsigned int my_psk_client_callback(WOLFSSL *ssl, const char *hint,
                                    char *identity, unsigned int id_max_len,
                                    unsigned char *key, unsigned int key_max_len);

K_SEM_DEFINE(lte_connected, 0, 1);

static void lte_handler(const struct lte_lc_evt *const evt);
static int modem_configure(void);

void setup_cert(WOLFSSL_CTX *ctx);
void show_supported_ciphers();
struct coap_packet create_coap_message(int *tempgrowth, uint8_t *send_buffer, size_t buffer_size);

int main(void)
{
        int sockfd;
        static struct sockaddr_in serverAddr;
        int ret, err, n;
        int cid = -1;
        uint8_t receive_buffer[BUFFER_SIZE];
        uint8_t send_buffer[BUFFER_SIZE];
        WOLFSSL_CTX *ctx;
        WOLFSSL *ssl;

        // Initialize GPIO pins; need also input mode to read them from PPK2
        gpio_pin_configure_dt(&profiler_pin_10, GPIO_OUTPUT_INACTIVE | GPIO_INPUT);
        gpio_pin_configure_dt(&profiler_pin_11, GPIO_OUTPUT_INACTIVE | GPIO_INPUT);

#ifdef USE_DTLS_1_3
        WOLFSSL_METHOD *method = wolfDTLSv1_3_client_method();
#else
        WOLFSSL_METHOD *method = wolfDTLSv1_2_client_method();
#endif
        ret = modem_configure();
        if (ret)
        {
                LOG_ERR("Failed to configure the modem");
                return 0;
        }
        // socket setup
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

        wolfSSL_Init();

#ifdef SHOW_WOLFSSL_DEBUG
        wolfSSL_SetLoggingCb(CustomLoggingCallback); // Comment out to get debug without timestamps (makes it a bit faster)
        wolfSSL_Debugging_ON();
        show_supported_ciphers(); // Comment out to NOT see the list of supported ciphes for your build
#endif

        ctx = wolfSSL_CTX_new(method);

#ifdef USE_CERTS
        setup_cert(ctx);
#ifdef USE_DTLS_1_3
        wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256"); // Force specific DTLS 1.3 ciphers
#else
        wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256"); // Force specific DTLS 1.2 ciphers
#endif
#else
        wolfSSL_CTX_use_psk_identity_hint(ctx, PSK_IDENTITY);
        wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_callback);
#ifdef USE_DTLS_1_3
        wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256"); // Force specific DTLS 1.3 PSK ciphers
#else
        wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-PSK-AES128-GCM-SHA256"); // Force specific DTLS 1.2 PSK ciphers
#endif
#endif
        ssl = wolfSSL_new(ctx);

        wolfSSL_dtls_set_peer(ssl, &serverAddr, sizeof(serverAddr));
        wolfSSL_set_fd(ssl, sockfd);
        // wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_X25519);
        wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);

#ifdef USE_CID
        cid = wolfSSL_dtls_cid_use(ssl);
#endif
        wolfSSL_dtls_set_timeout_init(ssl, 4);
        LOG_INF(GREEN "GPIO-Pin set? %d" RESET, device_is_ready(profiler_pin_10.port));
        LOG_INF(GREEN "GPIO-Pin set? %d" RESET, device_is_ready(profiler_pin_11.port));
        /* Perform DTLS connection */
        gpio_pin_set(profiler_pin_11.port, profiler_pin_11.pin, 1); // Turn GPIO ON
        LOG_INF(GREEN "Set GPIO pin 11 high. First Handshake\n" RESET);

#ifdef MEMORY_DEBUG_SHOW
        InitMemoryTracker();
#endif
        if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS)
        {
                err = wolfSSL_get_error(ssl, 0);
                LOG_ERR("wolfSSL_connect failed %d, %s", err, wolfSSL_ERR_reason_error_string(err));
                goto cleanup;
        }
        else
        {
                gpio_pin_set(profiler_pin_11.port, profiler_pin_11.pin, 0); // Turn GPIO OFF
                LOG_INF(GREEN "mwolfSSL handshake successful" RESET);
                LOG_INF(GREEN "Set GPIO pin 11 low. After first handshake\n" RESET);
#ifdef MEMORY_DEBUG_SHOW
                ShowMemoryTracker();
#endif
        }
        ret = wolfSSL_dtls_cid_is_enabled(ssl);
        if (ret == WOLFSSL_SUCCESS)
        {
                LOG_INF(GREEN "CID enabled" RESET);
        }
        else
        {
                err = wolfSSL_get_error(ssl, 0);
                LOG_INF(GREEN "CID not enabled" RESET);
        }

        int tempgrowth = 0;
        n = COAP_MAX;
        while (true)
        {
                if (gpio_pin_get(profiler_pin_10.port, profiler_pin_10.pin) != 1)
                {
                        LOG_INF(GREEN "Set GPIO pin 10 high. Before sending CoAP\n" RESET);
                        gpio_pin_set(profiler_pin_10.port, profiler_pin_10.pin, 1); // Turn GPIO ON
#ifdef MEMORY_DEBUG_SHOW
                        LOG_INF(GREEN "Memory Tracker init\n" RESET);
                        InitMemoryTracker();
#endif
                }
                // create and send coap PUT confirmable message
                struct coap_packet coap_message = create_coap_message(&tempgrowth, send_buffer, sizeof(send_buffer));
                ret = wolfSSL_write(ssl, coap_message.data, coap_message.offset);
                if (ret <= 0)
                {
                        err = wolfSSL_get_error(ssl, ret);
                        LOG_ERR("Error during wolfSSL_write: %d", err);
                        break;
                }
                // wait for ACK for 5 seconds
                struct pollfd fds;
                fds.fd = wolfSSL_get_fd(ssl);
                fds.events = POLLIN;

                ret = poll(&fds, 1, 5000);
                if (ret > 0 && (fds.revents & POLLIN))
                {
                        ret = wolfSSL_read(ssl, receive_buffer, sizeof(receive_buffer) - 1);
                        verify_coap_message(receive_buffer, ret);
                }
                else
                {
                        // no ACK received after 5 seconds, assume IP change and retry DTLS handshake
                        LOG_WRN(GREEN "No Ack received, assuming IP change, retry DTLS Handshake" RESET);
                        // wolfssl session needs to be reset and handshake started again
                        wolfSSL_free(ssl);
                        ssl = wolfSSL_new(ctx);
                        wolfSSL_set_fd(ssl, sockfd);
                        wolfSSL_dtls_set_peer(ssl, &serverAddr, sizeof(serverAddr));
                        wolfSSL_dtls_set_timeout_init(ssl, 3);
                        if (cid == WOLFSSL_SUCCESS)
                        {
                                wolfSSL_dtls_cid_use(ssl);
                        }
                        LOG_INF(GREEN "Set GPIO pin 11 high\n" RESET);
                        gpio_pin_set(profiler_pin_11.port, profiler_pin_11.pin, 1); // Turn GPIO ON
                        ret = wolfSSL_connect(ssl);
                        LOG_INF(GREEN "Set GPIO pin low\n" RESET);
                        gpio_pin_set(profiler_pin_11.port, profiler_pin_11.pin, 0); // Turn GPIO OFF
                        if (ret != WOLFSSL_SUCCESS)
                        {
                                LOG_ERR("Handshake failed");
                                break;
                        }
                        else
                        {
                                LOG_INF(GREEN "Set GPIO pin low\n" RESET);
                                continue;
                        }
                }
                LOG_INF(GREEN "Set GPIO pin low\n" RESET);
                gpio_pin_set(profiler_pin_10.port, profiler_pin_10.pin, 0); // Turn GPIO OFF
#ifdef MEMORY_DEBUG_SHOW
                LOG_INF(GREEN "Memory Tracker show\n" RESET);
                ShowMemoryTracker();
#endif
                n--;
                if (n == 0)
                {
                        goto cleanup;
                }
                k_sleep(K_SECONDS(COAP_INTERVAL));
        }

cleanup:

        ret = wolfSSL_shutdown(ssl);

        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
        {
                LOG_WRN("Waiting for peer close notify response");

                int retry_count = 0;
                const int max_retries = 50; // Adjust as needed

                // Wait for the server's close_notify without resending one
                while (ret == WOLFSSL_SHUTDOWN_NOT_DONE && retry_count < max_retries)
                {
                        k_sleep(K_MSEC(100));        // Wait for 100 ms before checking again
                        ret = wolfSSL_shutdown(ssl); // Check the status of the shutdown, do not resend close_notify
                        retry_count++;
                }
        }

        if (ret == 0)
        {
                LOG_INF(GREEN "Shutdown success" RESET);
        }
        else if (ret == 1)
        {
                LOG_INF(GREEN "Shutdown complete, peer sent close notify" RESET);
        }
        else
        {
                err = wolfSSL_get_error(ssl, ret);
                LOG_ERR("Shutdown failed: err = %d, %s", err, wolfSSL_ERR_reason_error_string(err));
        }

        wolfSSL_free(ssl);

        close(sockfd);
        if (ctx != NULL)
                wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        return 0;
}

// creates a coap PUT Confirmable message with a simulated temperature value
struct coap_packet create_coap_message(int *tempgrowth, uint8_t *send_buffer, size_t buffer_size)
{
        int temperature = 1 + (*tempgrowth)++;
        if (temperature == 1000)
        {
                *tempgrowth = 0;
        }
        LOG_INF(GREEN "Temperature: %d degrees" RESET, temperature);
        struct coap_packet coap_message;
        coap_packet_init(&coap_message, send_buffer, buffer_size, 1, COAP_TYPE_CON, 1, coap_next_token(), COAP_METHOD_PUT, coap_next_id());
        coap_packet_append_payload_marker(&coap_message);
        char payload[16];
        snprintf(payload, sizeof(payload), "%d", temperature); // Format the temperature as a string
        coap_packet_append_payload(&coap_message, (uint8_t *)payload, strlen(payload));
        LOG_HEXDUMP_DBG(payload, strlen(payload), GREEN "Payload" RESET);
        LOG_HEXDUMP_DBG(send_buffer, coap_message.offset, GREEN "coapmessage: " RESET);
        LOG_INF("Sent message ID: %d", coap_header_get_id(&coap_message));
        return coap_message;
}

void verify_coap_message(uint8_t *receive_buffer, int ret)
{
        LOG_HEXDUMP_DBG(receive_buffer, ret, GREEN "Data received" RESET);

        struct coap_packet response;
        int parse_ret = coap_packet_parse(&response, receive_buffer, ret, NULL, 0);
        if (parse_ret < 0)
        {
                LOG_ERR("Failed to parse CoAP message: %d", parse_ret);
                return;
        }
        uint8_t type = coap_header_get_type(&response);
        if (type == COAP_TYPE_ACK)
        {
                LOG_INF("Received CoAP ACK");
        }
        else
        {
                LOG_INF("Received non-ACK CoAP message (type: %d)", type);
        }
        uint8_t token[8];
        uint8_t token_len = coap_header_get_token(&response, token);
        LOG_HEXDUMP_DBG(token, token_len, "Print Token");

        // Get the message ID
        uint16_t message_id = coap_header_get_id(&response);
        LOG_INF(GREEN "Received Message ID in Ack: %d" RESET, message_id);
        return;
}

unsigned int my_psk_client_callback(WOLFSSL *ssl, const char *hint,
                                    char *identity, unsigned int id_max_len,
                                    unsigned char *key, unsigned int key_max_len)
{
        strncpy(identity, PSK_IDENTITY, id_max_len);
        memcpy(key, PSK_KEY, PSK_KEY_LEN);
        return PSK_KEY_LEN;
}

static void lte_handler(const struct lte_lc_evt *const evt)
{
        switch (evt->type)
        {
        case LTE_LC_EVT_NW_REG_STATUS:
                if ((evt->nw_reg_status != LTE_LC_NW_REG_REGISTERED_HOME) &&
                    (evt->nw_reg_status != LTE_LC_NW_REG_REGISTERED_ROAMING))
                {
                        break;
                }
                LOG_INF("Network registration status: %s",
                        evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ? "Connected - home network" : "Connected - roaming");
                k_sem_give(&lte_connected);
                break;
        case LTE_LC_EVT_RRC_UPDATE:
                LOG_INF("RRC mode: %s", evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ? "Connected" : "Idle");
                break;
        default:
                break;
        }
}

static int modem_configure(void)
{
        int err;

        LOG_INF("Initializing modem library");

        err = nrf_modem_lib_init();
        if (err)
        {
                LOG_ERR("Failed to initialize the modem library, error: %d", err);
                return err;
        }

        LOG_INF("Connecting to LTE network");
        err = lte_lc_connect_async(lte_handler);
        if (err)
        {
                LOG_ERR("Error in lte_lc_connect_async, error: %d", err);
                return err;
        }

        k_sem_take(&lte_connected, K_FOREVER);
        LOG_INF("Connected to LTE network");
        return 0;
}

void setup_cert(WOLFSSL_CTX *ctx)
{
        int ret;
        ret = wolfSSL_CTX_load_verify_buffer_ex(ctx, rootCA1_der, rootCA1_der_len, WOLFSSL_FILETYPE_ASN1, 0, (WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY));
        if (ret == WOLFSSL_SUCCESS)
        {
                LOG_INF("Root cert load success");
        }
        else
        {
                LOG_ERR("Root cert load failure: %s", wolfSSL_ERR_reason_error_string(ret));
        }

        ret = wolfSSL_CTX_use_certificate_buffer(ctx, client_cert_der, client_cert_der_len, WOLFSSL_FILETYPE_ASN1);
        if (ret == WOLFSSL_SUCCESS)
        {
                LOG_INF(GREEN "Client cert load success" RESET);
        }
        else
        {
                LOG_ERR("Client cert load failure: %s", wolfSSL_ERR_reason_error_string(ret));
        }

        ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, client_key_der, client_key_der_len, WOLFSSL_FILETYPE_ASN1);
        if (ret == WOLFSSL_SUCCESS)
        {
                LOG_INF(GREEN "Client key load success" RESET);
        }
        else
        {
                LOG_ERR("client key load fail Error: err = %s", wolfSSL_ERR_reason_error_string(ret));
        }
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
}

void CustomLoggingCallback(const int logLevel, const char *const logMessage)
{
        LOG_INF("WolfSSL: %s", logMessage);
}

void show_supported_ciphers()
{
        uint8_t cipher_buffer[2048];
        wolfSSL_get_ciphers(cipher_buffer, BUFFER_SIZE);
        for (char *p = (char *)cipher_buffer; *p; p++) // bring ":" separated list into readable format"
        {
                if (*p == ':')
                {
                        *p = '\n';
                }
        }
        LOG_INF("Enabled Ciphers:\n%s\n", cipher_buffer);
}
