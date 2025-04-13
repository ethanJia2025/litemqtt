/**
 * @file port_tcp_ssl.c
 * @brief TCP SSL functionality adaptation interface.
 * 
 * This file provides adaptation interfaces for TCP SSL functionality.
 * If CONFIG_SUPPORT_TLS is set to 1, users must implement the port_ssl_xxx 
 * interfaces defined in this file to enable MQTT client TCP SSL support.
 * If CONFIG_SUPPORT_TLS is set to 0, this file can be ignored and there
 * is no need to implement any port_ssl_xxx related interfaces.
 * 
 * @note
 * 该文件提供TCP SSL功能的适配接口。
 * 当CONFIG_SUPPORT_TLS配置为1时，用户需要实现本文件中定义的port_ssl_xxx
 * 接口，以支持MQTT客户端的TCP SSL功能；
 * 
 * 当CONFIG_SUPPORT_TLS配置为0时，可以忽略本文件，无需实现port_ssl_xxx
 * 相关接口。
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include "mqtt_client_err_code.h"
#include "mqtt_client_config.h"

#ifdef CONFIG_SUPPORT_TLS
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#endif


extern void *port_malloc(uint32_t size);
extern void port_free(void *ptr);
extern uint64_t _linux_get_time_ms(void);
extern uint64_t _linux_time_left(uint64_t t_end, uint64_t t_now);


#ifdef CONFIG_SUPPORT_TLS

typedef struct _TLSDataParams {
    mbedtls_ssl_context ssl;          /**< mbed TLS control context. */
    mbedtls_net_context fd;           /**< mbed TLS network context. */
    mbedtls_ssl_config conf;          /**< mbed TLS configuration context. */
    mbedtls_x509_crt cacertl;         /**< mbed TLS CA certification. */
    mbedtls_x509_crt clicert;         /**< mbed TLS Client certification. */
    mbedtls_pk_context pkey;          /**< mbed TLS Client key. */
} TLSDataParams_t, *TLSDataParams_pt;

static unsigned int mbedtls_mem_used = 0;
static unsigned int mbedtls_max_mem_used = 0;

#define SEND_TIMEOUT_SECONDS                (10)
#define MBEDTLS_MEM_INFO_MAGIC              0x12345678
#ifndef CONFIG_MBEDTLS_DEBUG_LEVEL
#define CONFIG_MBEDTLS_DEBUG_LEVEL 0
#endif

#define FORCE_SSL_VERIFY

typedef struct {
    int magic;
    int size;
} mbedtls_mem_info_t;


static unsigned int _avRandom()
{
    return (((unsigned int)rand() << 16) + rand());
}

static int _ssl_random(void *p_rng, unsigned char *output, size_t output_len)
{
    uint32_t rnglen = output_len;
    uint8_t   rngoffset = 0;

    while (rnglen > 0) {
        *(output + rngoffset) = (unsigned char)_avRandom() ;
        rngoffset++;
        rnglen--;
    }
    return 0;
}

static void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    if (NULL != ctx) {
        printf("%s\n", str);

    }
}

static int _real_confirm(int verify_result)
{
    printf("certificate verification result: 0x%02x\n", verify_result);

#if defined(FORCE_SSL_VERIFY)
    if ((verify_result & MBEDTLS_X509_BADCERT_EXPIRED) != 0) {
        printf("! fail ! ERROR_CERTIFICATE_EXPIRED\n");
        return -1;
    }

    if ((verify_result & MBEDTLS_X509_BADCERT_REVOKED) != 0) {
        printf("! fail ! server certificate has been revoked\n");
        return -1;
    }

    if ((verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0) {
        printf("! fail ! CN mismatch\n");
        return -1;
    }

    if ((verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0) {
        printf("! fail ! self-signed or not signed by a trusted CA\n");
        return -1;
    }
#endif

    return 0;
}

static int _ssl_client_init(mbedtls_ssl_context *ssl,
                            mbedtls_net_context *tcp_fd,
                            mbedtls_ssl_config *conf,
                            mbedtls_x509_crt *crt509_ca, const char *ca_crt, size_t ca_len,
                            mbedtls_x509_crt *crt509_cli, const char *cli_crt, size_t cli_len,
                            mbedtls_pk_context *pk_cli, const char *cli_key, size_t key_len,  const char *cli_pwd, size_t pwd_len
                           )
{
    int ret = -1;

    /*
     * 0. Initialize the RNG and the session data
     */
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold((int)CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif
    mbedtls_net_init(tcp_fd);
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_x509_crt_init(crt509_ca);

    /*verify_source->trusted_ca_crt==NULL
     * 0. Initialize certificates
     */

    printf("Loading the CA root certificate ...\n");
    if (NULL != ca_crt) {
        if (0 != (ret = mbedtls_x509_crt_parse(crt509_ca, (const unsigned char *)ca_crt, ca_len))) {
            printf(" failed ! x509parse_crt returned -0x%04x\n", -ret);
            return ret;
        }
    }
    printf(" ok (%d skipped)\n", ret);


    // Setup Client Cert/Key 
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_CERTS_C)
    mbedtls_x509_crt_init(crt509_cli);
    mbedtls_pk_init(pk_cli);
#endif
    if (cli_crt != NULL && cli_key != NULL) {
#if defined(MBEDTLS_CERTS_C)
        printf("start prepare client cert .\n");
        ret = mbedtls_x509_crt_parse(crt509_cli, (const unsigned char *) cli_crt, cli_len);
#else
        {
            ret = 1;
            printf("MBEDTLS_CERTS_C not defined.\n");
        }
#endif
        if (ret != 0) {
            printf(" failed!  mbedtls_x509_crt_parse returned -0x%x\n", -ret);
            return ret;
        }

#if defined(MBEDTLS_CERTS_C)
        printf("start mbedtls_pk_parse_key[%s]\n", cli_pwd);
        ret = mbedtls_pk_parse_key(pk_cli, (const unsigned char *) cli_key, key_len, (const unsigned char *) cli_pwd, pwd_len);
#else
        {
            ret = 1;
            printf("MBEDTLS_CERTS_C not defined.\n");
        }
#endif

        if (ret != 0) {
            printf(" failed\n  !  mbedtls_pk_parse_key returned -0x%x\n", -ret);
            return ret;
        }
    }
#endif // MBEDTLS_X509_CRT_PARSE_C 

    return 0;
}


static int net_prepare(void)
{
    signal(SIGPIPE, SIG_IGN);
    return (0);
}


static int mbedtls_net_connect_timeout(mbedtls_net_context *ctx, const char *host,
                                       const char *port, int proto, unsigned int timeout)
{
    int ret;
    struct addrinfo hints, *addr_list, *cur;
    struct timeval sendtimeout;
    uint8_t dns_retry = 0;

    if ((ret = net_prepare()) != 0) {
        return (ret);
    }

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    while(dns_retry++ < 8) {
        ret = getaddrinfo(host, port, &hints, &addr_list);
        if (ret != 0) {
            printf("getaddrinfo error[%d], res: %s, host: %s, port: %s\n", dns_retry, gai_strerror(ret), host, port);
            sleep(1);
            continue;
        }else{
            break;
        }
    }

    if (ret != 0) {
        return (MBEDTLS_ERR_NET_UNKNOWN_HOST);
    }

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        char ip4_str[INET_ADDRSTRLEN];

        ctx->fd = (int) socket(cur->ai_family, cur->ai_socktype,
                               cur->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        sendtimeout.tv_sec = timeout;
        sendtimeout.tv_usec = 0;

        if (0 != setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &sendtimeout, sizeof(sendtimeout))) {
            perror("setsockopt");
            printf("setsockopt error\n");
        }
        printf("setsockopt SO_SNDTIMEO timeout: %ds\n", (int)sendtimeout.tv_sec);

        inet_ntop(AF_INET, &((const struct sockaddr_in *)cur->ai_addr)->sin_addr, ip4_str, INET_ADDRSTRLEN);
        printf("connecting IP_ADDRESS: %s\n", ip4_str);

        if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            ret = 0;
            break;
        }

        close(ctx->fd);
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo(addr_list);

    return (ret);
}


static void *_SSLCalloc_wrapper(size_t n, size_t size)
{
    unsigned char *buf = NULL;
    mbedtls_mem_info_t *mem_info = NULL;

    if (n == 0 || size == 0) {
        return NULL;
    }

    buf = (unsigned char *)(port_malloc(n * size + sizeof(mbedtls_mem_info_t)));
    if (NULL == buf) {
        return NULL;
    } else {
        memset(buf, 0, n * size + sizeof(mbedtls_mem_info_t));
    }

    mem_info = (mbedtls_mem_info_t *)buf;
    mem_info->magic = MBEDTLS_MEM_INFO_MAGIC;
    mem_info->size = n * size;
    buf += sizeof(mbedtls_mem_info_t);

    mbedtls_mem_used += mem_info->size;
    if (mbedtls_mem_used > mbedtls_max_mem_used) {
        mbedtls_max_mem_used = mbedtls_mem_used;
    }

    /* printf("INFO -- mbedtls malloc: %p %d  total used: %d  max used: %d\r\n",
                       buf, (int)size, mbedtls_mem_used, mbedtls_max_mem_used); */

    return buf;
}

static void _SSLFree_wrapper(void *ptr)
{
    mbedtls_mem_info_t *mem_info = NULL;
    if (NULL == ptr) {
        return;
    }

    mem_info = (mbedtls_mem_info_t *)((unsigned char *)ptr - sizeof(mbedtls_mem_info_t));
    if (mem_info->magic != MBEDTLS_MEM_INFO_MAGIC) {
        printf("Warning - invalid mem info magic: 0x%x\r\n", mem_info->magic);
        return;
    }

    mbedtls_mem_used -= mem_info->size;
    /* printf("INFO mbedtls free: %p %d  total used: %d  max used: %d\r\n",
                       ptr, mem_info->size, mbedtls_mem_used, mbedtls_max_mem_used);*/

    port_free(mem_info);
}

/**
 * @brief This function connects to the specific SSL server with TLS, and returns a value that indicates whether the connection is create successfully or not. Call #NewNetwork() to initialize network structure before calling this function.
 * @param[in] n is the the network structure pointer.
 * @param[in] addr is the Server Host name or IP address.
 * @param[in] port is the Server Port.
 * @param[in] ca_crt is the Server's CA certification.
 * @param[in] ca_crt_len is the length of Server's CA certification.
 * @param[in] client_crt is the client certification.
 * @param[in] client_crt_len is the length of client certification.
 * @param[in] client_key is the client key.
 * @param[in] client_key_len is the length of client key.
 * @param[in] client_pwd is the password of client key.
 * @param[in] client_pwd_len is the length of client key's password.
 * @param[in] CN_hostname   is the CN info in the CA
 * @sa #NewNetwork();
 * @return If the return value is 0, the connection is created successfully. If the return value is -1, then calling lwIP #socket() has failed. If the return value is -2, then calling lwIP #connect() has failed. Any other value indicates that calling lwIP #getaddrinfo() has failed.
 */
static int _TLSConnectNetwork(TLSDataParams_t *pTlsData, const char *addr, const char *port,
                              const char *ca_crt, size_t ca_crt_len,
                              const char *client_crt,   size_t client_crt_len,
                              const char *client_key,   size_t client_key_len,
                              const char *client_pwd, size_t client_pwd_len, 
                              const char *CN_hostname)
{
    int ret = -1;
    /*
     * 0. Init
     */
    if (0 != (ret = _ssl_client_init(&(pTlsData->ssl), &(pTlsData->fd), &(pTlsData->conf),
                                     &(pTlsData->cacertl), ca_crt, ca_crt_len,
                                     &(pTlsData->clicert), client_crt, client_crt_len,
                                     &(pTlsData->pkey), client_key, client_key_len, client_pwd, client_pwd_len))) {
        printf(" failed ! ssl_client_init returned -0x%04x\n", -ret);
        return ret;
    }

    /*
     * 1. Start the connection
     */
    printf("Connecting to /%s/%s...\n", addr, port);
    if (0 != (ret = mbedtls_net_connect_timeout(&(pTlsData->fd), addr, port, MBEDTLS_NET_PROTO_TCP,
                    SEND_TIMEOUT_SECONDS))) {
        printf(" failed ! net_connect returned -0x%04x\n", -ret);
        return ret;
    }

    printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    printf("  . Setting up the SSL/TLS structure...\n");
    if ((ret = mbedtls_ssl_config_defaults(&(pTlsData->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf(" failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        return ret;
    }

    mbedtls_ssl_conf_max_version(&pTlsData->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&pTlsData->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    printf(" ok\n");

    /* OPTIONAL is not optimal for security, but makes interop easier in this simplified example */
    if (ca_crt != NULL) {
#if defined(FORCE_SSL_VERIFY)
        mbedtls_ssl_conf_authmode(&(pTlsData->conf), MBEDTLS_SSL_VERIFY_REQUIRED);
#else
        mbedtls_ssl_conf_authmode(&(pTlsData->conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif
    } else {
        mbedtls_ssl_conf_authmode(&(pTlsData->conf), MBEDTLS_SSL_VERIFY_NONE);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_conf_ca_chain(&(pTlsData->conf), &(pTlsData->cacertl), NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(&(pTlsData->conf), &(pTlsData->clicert), &(pTlsData->pkey))) != 0) {
        printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        return ret;
    }
#endif
    mbedtls_ssl_conf_rng(&(pTlsData->conf), _ssl_random, NULL);
    mbedtls_ssl_conf_dbg(&(pTlsData->conf), _ssl_debug, NULL);
    mbedtls_ssl_conf_dbg(&(pTlsData->conf), _ssl_debug, stdout);

    if ((ret = mbedtls_ssl_setup(&(pTlsData->ssl), &(pTlsData->conf))) != 0) {
        printf("failed! mbedtls_ssl_setup returned %d\n", ret);
        return ret;
    }
#if defined(ON_PRE) || defined(ON_DAILY)
    printf("SKIPPING mbedtls_ssl_set_hostname() when ON_PRE or ON_DAILY defined!\n");
#else
    //mbedtls_ssl_set_hostname(&(pTlsData->ssl), CN_name);
    mbedtls_ssl_set_hostname(&(pTlsData->ssl), CN_hostname);
#endif
    mbedtls_ssl_set_bio(&(pTlsData->ssl), &(pTlsData->fd), mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    /*
      * 4. Handshake
      */
    mbedtls_ssl_conf_read_timeout(&(pTlsData->conf), 10000);
    printf("Performing the SSL/TLS handshake...\n");

    while ((ret = mbedtls_ssl_handshake(&(pTlsData->ssl))) != 0) {
        if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            printf("failed  ! mbedtls_ssl_handshake returned -0x%04x\n", -ret);
            return ret;
        }
    }
    printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    printf("  . Verifying peer X.509 certificate..\n");
    if (0 != (ret = _real_confirm(mbedtls_ssl_get_verify_result(&(pTlsData->ssl))))) {
        printf(" failed  ! verify result not confirmed.\n");
        return ret;
    }
    /* n->my_socket = (int)((n->tlsdataparams.fd).fd); */
    /* WRITE_IOT_DEBUG_LOG("my_socket=%d", n->my_socket); */

    return 0;

}

static int _network_ssl_read(TLSDataParams_t *pTlsData, char *buffer, int len, int timeout_ms)
{
    uint32_t        readLen = 0;
    static int      net_status = 0;
    int             ret = -1;
    char            err_str[33];

    mbedtls_ssl_conf_read_timeout(&(pTlsData->conf), timeout_ms);
    while (readLen < len) {
        ret = mbedtls_ssl_read(&(pTlsData->ssl), (unsigned char *)(buffer + readLen), (len - readLen));
        if (ret > 0) {
            readLen += ret;
            net_status = 0;
        } else if (ret == 0) {
            /* if ret is 0 and net_status is -2, indicate the connection is closed during last call */
            return (net_status == -2) ? net_status : readLen;
        } else {
            if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret) {
                mbedtls_strerror(ret, err_str, sizeof(err_str));
                printf("ssl recv error: code = %d, err_str = '%s'\n", ret, err_str);
                net_status = -2; /* connection is closed */
                break;
            } else if ((MBEDTLS_ERR_SSL_TIMEOUT == ret)
                       || (MBEDTLS_ERR_SSL_CONN_EOF == ret)
                       || (MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED == ret)
                       || (MBEDTLS_ERR_SSL_NON_FATAL == ret)) {
                /* read already complete */
                /* if call mbedtls_ssl_read again, it will return 0 (means EOF) */

                return readLen;
            } else {
                mbedtls_strerror(ret, err_str, sizeof(err_str));
                printf("ssl recv error: code = %d, err_str = '%s'\n", ret, err_str);
                net_status = -1;
                return -1; /* Connection error */
            }
        }
    }

    return (readLen > 0) ? readLen : net_status;
}

static int _network_ssl_write(TLSDataParams_t *pTlsData, const char *buffer, int len, int timeout_ms)
{

    int32_t res = 0;
    int32_t write_bytes = 0;
    uint64_t timestart_ms = 0, timenow_ms = 0;
    struct timeval timestart, timenow, timeout;

    if (pTlsData == NULL) {
        return -1;
    }

    /* timeout */
    timeout.tv_sec = timeout_ms/1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    /* Start Time */
    gettimeofday(&timestart, NULL);
    timestart_ms = timestart.tv_sec * 1000 + timestart.tv_usec / 1000;
    timenow_ms = timestart_ms;

    res = setsockopt(pTlsData->fd.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (res < 0) {
        return -1;
    }

    do {
        gettimeofday(&timenow, NULL);
        timenow_ms = timenow.tv_sec * 1000 + timenow.tv_usec / 1000;

        if (timenow_ms - timestart_ms >= timenow_ms ||
            timeout_ms - (timenow_ms - timestart_ms) > timeout_ms) {
            break;
        }

        res = mbedtls_ssl_write(&(pTlsData->ssl), (unsigned char *)buffer + write_bytes, len - write_bytes);
        if (res < 0) {
            if (res != MBEDTLS_ERR_SSL_WANT_READ &&
                res != MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (write_bytes == 0) {
                    return -1;
                }
                break;
            }
        }else if (res == 0) {
            break;
        }else{
            write_bytes += res;
        }
    }while(((timenow_ms - timestart_ms) < timeout_ms) && (write_bytes < len));

    return write_bytes;

}

static void _network_ssl_disconnect(TLSDataParams_t *pTlsData)
{
    mbedtls_ssl_close_notify(&(pTlsData->ssl));
    mbedtls_net_free(&(pTlsData->fd));
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free(&(pTlsData->cacertl));
    if ((pTlsData->pkey).pk_info != NULL) {
        printf("need release client crt&key\n");
#if defined(MBEDTLS_CERTS_C)
        mbedtls_x509_crt_free(&(pTlsData->clicert));
        mbedtls_pk_free(&(pTlsData->pkey));
#endif
    }
#endif
    mbedtls_ssl_free(&(pTlsData->ssl));
    mbedtls_ssl_config_free(&(pTlsData->conf));
    printf("ssl_disconnect\n");
}

int port_ssl_read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    return _network_ssl_read((TLSDataParams_t *)handle, buf, len, timeout_ms);;
}

int port_ssl_write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    return _network_ssl_write((TLSDataParams_t *)handle, buf, len, timeout_ms);
}

int32_t port_ssl_destroy(uintptr_t handle)
{
    if ((uintptr_t)NULL == handle) {
        printf("handle is NULL\n");
        return 0;
    }

    _network_ssl_disconnect((TLSDataParams_t *)handle);
    port_free((void *)handle);
    return 0;
}


uintptr_t port_ssl_establish(const char *host, uint16_t port,
                            const char *ca_crt, uint32_t ca_crt_len,
                            const char *client_crt, int client_crt_len,
                            const char *client_key, int client_key_len,
                            const char *client_pwd, int client_pwd_len,
                            const char *CN_hostname)
{
    char                port_str[6];
    const char         *alter = host;
    TLSDataParams_pt    pTlsData;

    if (host == NULL || ca_crt == NULL) {
        printf("input params are NULL, abort\n");
        return 0;
    }

    if (!strlen(host) || (strlen(host) < 8)) {
        printf("invalid host: '%s'(len=%d), abort\n", host, (int)strlen(host));
        return 0;
    }

    pTlsData = port_malloc(sizeof(TLSDataParams_t));
    if (NULL == pTlsData) {
        return (uintptr_t)NULL;
    }
    memset(pTlsData, 0x0, sizeof(TLSDataParams_t));

    sprintf(port_str, "%u", port);

#if defined(ON_PRE)
    if (!strcmp(GUIDER_ONLINE_HOSTNAME, host)) {
        printf("ALTERING '%s' to '%s' since ON_PRE defined!\n", host, GUIDER_PRE_ADDRESS);
        alter = GUIDER_PRE_ADDRESS;
    }
#endif

    mbedtls_platform_set_calloc_free(_SSLCalloc_wrapper, _SSLFree_wrapper);

    if (0 != _TLSConnectNetwork(pTlsData, alter, port_str, 
                        ca_crt, ca_crt_len, 
                        client_crt, client_crt_len,
                        client_key, client_key_len,
                        client_pwd, client_pwd_len, CN_hostname)) {
        _network_ssl_disconnect(pTlsData);
        port_free((void *)pTlsData);
        return (uintptr_t)NULL;
    }

    return (uintptr_t)pTlsData;
}


#endif



