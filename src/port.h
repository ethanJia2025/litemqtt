/**
 * @file port.h
 * @brief LiteMQTT porting layer
 * 
 * This file provides the necessary functions to port LiteMQTT to different platforms.
 * 
 */


#ifndef __LITE_MQTT_PORT_H
#define __LITE_MQTT_PORT_H

#include <stdint.h>
#include "mqtt_client_config.h"


void port_printf(const char *fmt, ...);
void port_free(void *ptr);
void *port_malloc(uint32_t size);
void *port_mutex_create(void);
void port_mutex_destroy(void *mutex);
void port_mutex_lock(void *mutex);
void port_mutex_unlock(void *mutex);
void port_sleep_ms(uint32_t ms);
uint64_t port_uptime_ms(void);

#ifdef CONFIG_SUPPORT_TLS
int port_ssl_read(uintptr_t handle, char *buf, int len, int timeout_ms);
int port_ssl_write(uintptr_t handle, const char *buf, int len, int timeout_ms);
int32_t port_ssl_destroy(uintptr_t handle);
uintptr_t port_ssl_establish(const char *host, uint16_t port,
    const char *ca_crt, uint32_t ca_crt_len,
    const char *client_crt, int client_crt_len,
    const char *client_key, int client_key_len,
    const char *client_pwd, int client_pwd_len,
    const char *CN_hostname);
#else
int port_tcp_destroy(uintptr_t fd);
uintptr_t port_tcp_establish(const char *host, uint16_t port);
int32_t port_tcp_read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms);
int32_t port_tcp_write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms);
#endif


#endif