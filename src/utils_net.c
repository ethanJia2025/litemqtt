#include "mqtt_client_config.h"
#include "utils_net.h"
#include <stddef.h>
#include <string.h>
#include "port.h"


void port_printf(const char *fmt, ...);

#define net_err(...)      do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)


#ifdef CONFIG_SUPPORT_TLS
typedef struct{
    void *(*malloc)(uint32_t size);
    void (*free)(void *ptr);
} ssl_hooks_t;



static void *ssl_malloc(uint32_t size)
{
    return port_malloc(size);
}
static void ssl_free(void *ptr)
{
    port_free(ptr);
}

uintptr_t port_ssl_establish(const char *host, uint16_t port,
                            const char *ca_crt, uint32_t ca_crt_len,
                            const char *client_crt, int client_crt_len,
                            const char *client_key, int client_key_len,
                            const char *client_pwd, int client_pwd_len,
                            const char *CN_hostname);
int32_t port_ssl_destroy(uintptr_t handle);
int port_ssl_read(uintptr_t handle, char *buf, int len, int timeout_ms);
int port_ssl_write(uintptr_t handle, const char *buf, int len, int timeout_ms);
int ssl_hooks_set(ssl_hooks_t *hooks);

static int read_ssl(utils_network_pt pNetwork, char *buffer, uint32_t len, uint32_t timeout_ms)
{
    if (NULL == pNetwork) {
        net_err("network is null");
        return -1;
    }

    return port_ssl_read((uintptr_t)pNetwork->handle, buffer, len, timeout_ms);
}

static int write_ssl(utils_network_pt pNetwork, const char *buffer, uint32_t len, uint32_t timeout_ms)
{
    if (NULL == pNetwork) {
        net_err("network is null");
        return -1;
    }

    return port_ssl_write((uintptr_t)pNetwork->handle, buffer, len, timeout_ms);
}

static int disconnect_ssl(utils_network_pt pNetwork)
{
    if (NULL == pNetwork) {
        net_err("network is null");
        return -1;
    }

    port_ssl_destroy((uintptr_t)pNetwork->handle);
    pNetwork->handle = 0;

    return 0;
}

static int connect_ssl(utils_network_pt pNetwork)
{
    ssl_hooks_t ssl_hooks;

    if (NULL == pNetwork) {
        net_err("network is null");
        return 1;
    }

#ifdef INFRA_MEM_STATS
    memset(&ssl_hooks, 0, sizeof(ssl_hooks_t));
    ssl_hooks.malloc = ssl_malloc;
    ssl_hooks.free = ssl_free;

    ssl_hooks_set(&ssl_hooks);
#else
    (void)ssl_hooks;
#endif

    if (0 != (pNetwork->handle = (intptr_t)port_ssl_establish(
            pNetwork->pHostAddress, pNetwork->port,
            pNetwork->ca_crt, pNetwork->ca_crt_len + 1,
            pNetwork->client_crt, pNetwork->client_crt_len + 1,
            pNetwork->client_key, pNetwork->client_key_len + 1,
            pNetwork->client_pwd, pNetwork->client_pwd_len + 1,
            pNetwork->CN_hostname))) {
        return 0;
    }
    else {
        /* TODO SHOLUD not remove this handle space */
        /* The space will be freed by calling disconnect_ssl() */
        /* utils_memory_free((void *)pNetwork->handle); */
#ifdef INFRA_EVENT
        iotx_event_post(IOTX_CONN_CLOUD_FAIL);
#endif
        return -1;
    }
}
#endif

uintptr_t port_tcp_establish(const char *host, uint16_t port);
int port_tcp_destroy(uintptr_t fd);
int32_t port_tcp_write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms);
int32_t port_tcp_read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms);
void *port_malloc(uint32_t size);
void port_free(void *ptr);

/*** TCP connection ***/
static int read_tcp(utils_network_pt pNetwork, char *buffer, uint32_t len, uint32_t timeout_ms)
{
    return port_tcp_read(pNetwork->handle, buffer, len, timeout_ms);
}


static int write_tcp(utils_network_pt pNetwork, const char *buffer, uint32_t len, uint32_t timeout_ms)
{
    return port_tcp_write(pNetwork->handle, buffer, len, timeout_ms);
}

static int disconnect_tcp(utils_network_pt pNetwork)
{
    if (pNetwork->handle == (uintptr_t)(-1)) {
        net_err("Network->handle = -1");
        return -1;
    }

    port_tcp_destroy(pNetwork->handle);
    pNetwork->handle = (uintptr_t)(-1);
    return 0;
}

static int connect_tcp(utils_network_pt pNetwork)
{
    if (NULL == pNetwork) {
        net_err("network is null");
        return 1;
    }

    pNetwork->handle = port_tcp_establish(pNetwork->pHostAddress, pNetwork->port);
    if (pNetwork->handle == (uintptr_t)(-1)) {
        return -1;
    }

    return 0;
}



int utils_net_read(utils_network_pt pNetwork, char *buffer, uint32_t len, uint32_t timeout_ms)
{
    int ret = 0;
#ifdef CONFIG_SUPPORT_TLS
    if (NULL != pNetwork->ca_crt) {
        ret = read_ssl(pNetwork, buffer, len, timeout_ms);
    } else {
        ret = read_tcp(pNetwork, buffer, len, timeout_ms);
    }
#else
    /* 当TLS被禁用时，总是使用TCP，忽略ca_crt */
    ret = read_tcp(pNetwork, buffer, len, timeout_ms);
#endif
    return ret;
}

int utils_net_write(utils_network_pt pNetwork, const char *buffer, uint32_t len, uint32_t timeout_ms)
{
    int ret = 0;
#ifdef CONFIG_SUPPORT_TLS
    if (NULL != pNetwork->ca_crt) {
        ret = write_ssl(pNetwork, buffer, len, timeout_ms);
    } else {
        ret = write_tcp(pNetwork, buffer, len, timeout_ms);
    }
#else
    /* 当TLS被禁用时，总是使用TCP，忽略ca_crt */
    ret = write_tcp(pNetwork, buffer, len, timeout_ms);
#endif
    return ret;
}

int utils_net_disconnect(utils_network_pt pNetwork)
{
    int ret = 0;
#ifdef CONFIG_SUPPORT_TLS
    if (NULL != pNetwork->ca_crt) {
        ret = disconnect_ssl(pNetwork);
    } else {
        ret = disconnect_tcp(pNetwork);
    }
#else
    /* 当TLS被禁用时，总是使用TCP，忽略ca_crt */
    ret = disconnect_tcp(pNetwork);
#endif
    return ret;
}

int utils_net_connect(utils_network_pt pNetwork)
{
    int ret = 0;
#ifdef CONFIG_SUPPORT_TLS
    if (NULL != pNetwork->ca_crt) {
        ret = connect_ssl(pNetwork);
    } else {
        ret = connect_tcp(pNetwork);
    }
#else
    /* 当TLS被禁用时，总是使用TCP，忽略ca_crt */
    ret = connect_tcp(pNetwork);
#endif
    return ret;
}


int utils_net_init(utils_network_pt pNetwork, 
    const char *host, uint16_t port, const char *ca_crt, 
    const char *client_crt, const char *client_key, const char *client_pwd,
    const char *CN_hostname)
{
    if (!pNetwork || !host) {
        net_err("parameter error! pNetwork=%p, host = %p", pNetwork, host);
        return -1;
    }

    pNetwork->pHostAddress = host;
    pNetwork->port = port;
    
#ifdef CONFIG_SUPPORT_TLS
    pNetwork->ca_crt = ca_crt;

    if (NULL == ca_crt) {
        pNetwork->ca_crt_len = 0;
    } else {
        pNetwork->ca_crt_len = strlen(ca_crt);
    }
    pNetwork->ca_crt = ca_crt;

    if (NULL == client_crt) {
        pNetwork->client_crt_len = 0;
    } else {
        pNetwork->client_crt_len = strlen(client_crt);
    }
    pNetwork->client_crt = client_crt;

    if (NULL == client_key) {
        pNetwork->client_key_len = 0;
    } else {
        pNetwork->client_key_len = strlen(client_key);
    }
    pNetwork->client_key = client_key;

    if (NULL == client_pwd) {
        pNetwork->client_pwd_len = 0;
    } else {
        pNetwork->client_pwd_len = strlen(client_pwd);
    }
    pNetwork->client_pwd = client_pwd;
    
    pNetwork->CN_hostname = CN_hostname;
#else
    /* 当TLS被禁用时，确保所有证书相关字段都为NULL */
    pNetwork->ca_crt = NULL;
    pNetwork->ca_crt_len = 0;
    pNetwork->client_crt = NULL;
    pNetwork->client_crt_len = 0;
    pNetwork->client_key = NULL;
    pNetwork->client_key_len = 0;
    pNetwork->client_pwd = NULL;
    pNetwork->client_pwd_len = 0;
    pNetwork->CN_hostname = NULL;
#endif

    pNetwork->handle = 0;
    pNetwork->read = utils_net_read;
    pNetwork->write = utils_net_write;
    pNetwork->disconnect = utils_net_disconnect;
    pNetwork->connect = utils_net_connect;

    return 0;
}








