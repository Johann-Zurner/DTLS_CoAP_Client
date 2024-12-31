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

// #define USE_CID   // Comment out to NOT use Connection ID
// #define USE_CERTS // Comment out to use Pre Shared Keys instead of Certificate verification (don't forget same on server side)
// #define USE_DTLS_1_3       // Comment out to use DTLS 1.2 instead of 1.3
// #define SHOW_WOLFSSL_DEBUG // Comment out to not see WolfSSL Debug logs including timestamps
#define COAP_INTERVAL 7 // Set the time interval between CoAP PUT messages
#define COAP_MAX 500    // Set the maximum number of CoAP messages before DTLS session shuts down

#define LED0_NODE DT_ALIAS(led0) // LED0_NODE = led0 defined in the .dts file; Lights up when DTLS Handshake is successfull

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

static const struct gpio_dt_spec profiler_pin = {
    .port = DEVICE_DT_GET(DT_NODELABEL(gpio0)), // GPIO controller
    .pin = 10,                                  // Pin number
    .dt_flags = GPIO_OUTPUT_INACTIVE            // Initial state (inactive)
};

/* Choose the Zephyr log level
e.g. LOG_LEVEL_INF will print only your LOG_INF statements, LOG_LEVEL_ERR will print LOG_INF and LOG_ERR, etc.) */
LOG_MODULE_REGISTER(DTLS_CoAP_Project, LOG_LEVEL_NONE);

// Used for WolfSSL custom logging to add timestamps to each log output
void CustomLoggingCallback(const int logLevel, const char *const logMessage);

void monitor_memory_usage();
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

int main(void)
{
        int sockfd;
        static struct sockaddr_in serverAddr;
        int ret, err, n;
        int cid = -1;
        uint8_t send_buffer[BUFFER_SIZE];
        uint8_t receive_buffer[BUFFER_SIZE];
        struct coap_packet coap_message;
        WOLFSSL_CTX *ctx;
        WOLFSSL *ssl;
        const struct device *gpio_dev;

        InitMemoryTracker();
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
        wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
        wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_X25519);

#ifdef USE_CID
        cid = wolfSSL_dtls_cid_use(ssl);
#endif
        wolfSSL_dtls_set_timeout_init(ssl, 4);
        ShowMemoryTracker();
        LOG_INF("GPIO-Pin set? %d", device_is_ready(profiler_pin.port));
        gpio_pin_configure_dt(&profiler_pin, GPIO_OUTPUT_ACTIVE);
        // monitor_memory_usage();
        /* Perform DTLS connection */
        printf("Set GPIO pin high\n");
        gpio_pin_set(profiler_pin.port, profiler_pin.pin, 1); // Turn GPIO ON
        InitMemoryTracker();
        if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS)
        {
                err = wolfSSL_get_error(ssl, 0);
                LOG_ERR("wolfSSL_connect failed %d, %s", err, wolfSSL_ERR_reason_error_string(err));
                goto cleanup;
        }
        else
        {
                LOG_INF(GREEN "mwolfSSL handshake successful" RESET);
                ShowMemoryTracker();
                LOG_INF(GREEN "Set GPIO pin low\n" RESET);
                gpio_pin_set(profiler_pin.port, profiler_pin.pin, 0); // Turn GPIO OFF
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

        int k = 0;
        n = COAP_MAX;
        while (true)
        {
                LOG_INF(GREEN "Set GPIO pin high\n" RESET);
                gpio_pin_set(profiler_pin.port, profiler_pin.pin, 1); // Turn GPIO ON
                InitMemoryTracker();
                int temperature = 1 + (k++);
                if (temperature == 1000)
                {
                        temperature = 1;
                }
                LOG_INF(GREEN "Temperature: %d degrees" RESET, temperature);
                coap_packet_init(&coap_message, send_buffer, sizeof(send_buffer), 1, COAP_TYPE_CON, 1, coap_next_token(), COAP_METHOD_PUT, coap_next_id());
                coap_packet_append_payload_marker(&coap_message);
                char payload[16];
                snprintf(payload, sizeof(payload), "%d", temperature); // Format the temperature as a string
                coap_packet_append_payload(&coap_message, (uint8_t *)payload, strlen(payload));
                LOG_HEXDUMP_DBG(payload, strlen(payload), GREEN "Payload" RESET);

                LOG_HEXDUMP_DBG(send_buffer, coap_message.offset, GREEN "coapmessage: " RESET);
                LOG_INF("Sent message ID: %d", coap_header_get_id(&coap_message));
                ret = wolfSSL_write(ssl, coap_message.data, coap_message.offset);
                if (ret <= 0)
                {
                        err = wolfSSL_get_error(ssl, ret);
                        LOG_ERR("Error during wolfSSL_write: %d", err);
                        break;
                }
                struct pollfd fds;
                fds.fd = wolfSSL_get_fd(ssl);
                fds.events = POLLIN;

                ret = poll(&fds, 1, 5000);
                if (ret > 0 && (fds.revents & POLLIN))
                {
                        ret = wolfSSL_read(ssl, receive_buffer, sizeof(receive_buffer) - 1);
                        // k_sleep(K_SECONDS(5));
                        verify_coap_message(receive_buffer, ret);
                }
                else
                {
                        LOG_WRN(GREEN "No Ack received, assuming IP change, retry DTLS Handshake" RESET);
                        wolfSSL_free(ssl);
                        ssl = wolfSSL_new(ctx);
                        wolfSSL_set_fd(ssl, sockfd);
                        wolfSSL_dtls_set_peer(ssl, &serverAddr, sizeof(serverAddr));
                        wolfSSL_dtls_set_timeout_init(ssl, 3);
                        if (cid == WOLFSSL_SUCCESS)
                        {
                                wolfSSL_dtls_cid_use(ssl);
                        }
                        ret = wolfSSL_connect(ssl);
                        if (ret != WOLFSSL_SUCCESS)
                        {
                                LOG_ERR("Handshake failed");
                                break;
                        }
                        else
                        {
                                LOG_INF(GREEN "Set GPIO pin low\n" RESET);
                                gpio_pin_set(profiler_pin.port, profiler_pin.pin, 0); // Turn GPIO OFF
                                ShowMemoryTracker();
                                continue;
                        }
                }
                LOG_INF(GREEN "Set GPIO pin low\n" RESET);
		gpio_pin_set(profiler_pin.port, profiler_pin.pin, 0); // Turn GPIO OFF
                ShowMemoryTracker();
                k_sleep(K_SECONDS(COAP_INTERVAL));
                n--;
                if (n == 0)
                {
                        break;
                }
        }

cleanup:
        if (ssl != NULL)
        {
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
        }

        close(sockfd);
        if (ctx != NULL)
                wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        return 0;
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
        printf("Enabled Ciphers:\n%s\n", cipher_buffer);
}
