/**
 * @file port_base.c
 * @brief MQTT Client Adaptation Interface (适配接口)
 * 
 * This file defines the essential functions required for adapting the MQTT client.
 * Users must implement these functions to ensure proper integration with the platform.
 * 
 * 该文件定义了 MQTT 客户端的适配接口，包含必须实现的函数。
 * 使用者必须适配这些接口以确保与平台的正确集成。
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
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include "mqtt_client_err_code.h"

uint64_t _linux_get_time_ms(void)
{
    struct timeval tv = { 0 };
    uint64_t time_ms;

    gettimeofday(&tv, NULL);

    time_ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;

    return time_ms;
}

uint64_t _linux_time_left(uint64_t t_end, uint64_t t_now)
{
    uint64_t t_left;

    if (t_end > t_now) {
        t_left = t_end - t_now;
    } else {
        t_left = 0;
    }

    return t_left;
}



// 添加全局变量来跟踪内存使用情况
static uint32_t g_memory_used = 0;
static pthread_mutex_t g_memory_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief 获取当前已分配的内存总量
 *
 * @return 当前已分配但未释放的内存量（字节）
 */
uint32_t port_memory_usage(void)
{
    uint32_t usage;
    
    pthread_mutex_lock(&g_memory_mutex);
    usage = g_memory_used;
    pthread_mutex_unlock(&g_memory_mutex);
    
    return usage;
}


/**
 * @brief Deallocate memory block
 *
 * @param[in] ptr @n Pointer to a memory block previously allocated with platform_malloc.
 * @return None.
 * @see None.
 * @note None.
 */
#if 0
 void port_free(void *ptr)
{
    free(ptr);
}
#else
void port_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    
    // 获取此块内存的大小（存储在指针前面的4字节）
    uint32_t *size_ptr = (uint32_t *)ptr - 1;
    uint32_t block_size = *size_ptr;
    
    // 更新内存使用统计
    pthread_mutex_lock(&g_memory_mutex);
    g_memory_used -= block_size;
    pthread_mutex_unlock(&g_memory_mutex);
    
    // 释放实际的内存块（包括大小信息）
    free(size_ptr);
}
#endif



/**
 * @brief Allocates a block of size bytes of memory, returning a pointer to the beginning of the block.
 *
 * @param [in] size @n specify block size in bytes.
 * @return A pointer to the beginning of the block.
 * @see None.
 * @note Block value is indeterminate.
 */
#if 0
 void *port_malloc(uint32_t size)
{
    return malloc(size);
}
#else
void *port_malloc(uint32_t size)
{
    // 多分配4字节用于存储块大小
    uint32_t *block = (uint32_t *)malloc(size + sizeof(uint32_t));
    if (block == NULL) {
        return NULL;
    }
    
    // 在块的开始处存储大小信息
    *block = size;
    
    // 更新内存使用统计
    pthread_mutex_lock(&g_memory_mutex);
    g_memory_used += size;
    pthread_mutex_unlock(&g_memory_mutex);
    
    // 返回数据区的指针（跳过大小信息）
    return (void *)(block + 1);
}
#endif

/**
 * @brief Create a mutex.
 *
 * @retval NULL : Initialize mutex failed.
 * @retval NOT_NULL : The mutex handle.
 * @see None.
 * @note None.
 */
void *port_mutex_create(void)
{
    int err_num;
    pthread_mutex_t *mutex = (pthread_mutex_t *)port_malloc(sizeof(pthread_mutex_t));
    if (NULL == mutex) {
        return NULL;
    }

    if (0 != (err_num = pthread_mutex_init(mutex, NULL))) {
        printf("create mutex failed\n");
        port_free(mutex);
        return NULL;
    }

    return mutex;
}



/**
 * @brief Destroy the specified mutex object, it will release related resource.
 *
 * @param [in] mutex @n The specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void port_mutex_destroy(void *mutex)
{
    int err_num;

    if (!mutex) {
        printf("mutex want to destroy is NULL!\n");
        return;
    }
    if (0 != (err_num = pthread_mutex_destroy((pthread_mutex_t *)mutex))) {
        printf("destroy mutex failed\n");
    }

    port_free(mutex);
}


/**
 * @brief Waits until the specified mutex is in the signaled state.
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void port_mutex_lock(void *mutex)
{
    int err_num;
    if (0 != (err_num = pthread_mutex_lock((pthread_mutex_t *)mutex))) {
        printf("lock mutex failed: - '%s' (%d)\n", strerror(err_num), err_num);
    }
}


/**
 * @brief Releases ownership of the specified mutex object..
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void port_mutex_unlock(void *mutex)
{
    int err_num;
    if (0 != (err_num = pthread_mutex_unlock((pthread_mutex_t *)mutex))) {
        printf("unlock mutex failed - '%s' (%d)\n", strerror(err_num), err_num);
    }
}


/**
 * @brief Writes formatted data to stream.
 *
 * @param [in] fmt: @n String that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return None.
 * @see None.
 * @note None.
 */
void port_printf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    fflush(stdout);
}


/**
 * @brief Sleep thread itself.
 *
 * @param [in] ms @n the time interval for which execution is to be suspended, in milliseconds.
 * @return None.
 * @see None.
 * @note None.
 */
void port_sleep_ms(uint32_t ms)
{
    usleep(1000 * ms);
}




/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was boot.
 *
 * @return the number of milliseconds.
 * @see None.
 * @note None.
 */
uint64_t port_uptime_ms(void)
{
    uint64_t            time_ms;
    struct timespec     ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_ms = ((uint64_t)ts.tv_sec * (uint64_t)1000) + (ts.tv_nsec / 1000 / 1000);

    return time_ms;
}



/**
 * @brief Destroy the specific TCP connection.
 *
 * @param [in] fd: @n Specify the TCP connection by handle.
 *
 * @return The result of destroy TCP connection.
 * @retval < 0 : Fail.
 * @retval   0 : Success.
 */

 int port_tcp_destroy(uintptr_t fd)
 {
     int rc;
 
     /* Shutdown both send and receive operations. */
     rc = shutdown((int) fd, 2);
     if (0 != rc) {
         printf("shutdown error\n");
         return -1;
     }
 
     rc = close((int) fd);
     if (0 != rc) {
         printf("closesocket error\n");
         return -1;
     }
 
     return 0;
 }
 
 
 /**
  * @brief Establish a TCP connection.
  *
  * @param [in] host: @n Specify the hostname(IP) of the TCP server
  * @param [in] port: @n Specify the TCP port of TCP server
  *
  * @return The handle of TCP connection.
    @retval (uintptr_t)(-1): Fail.
    @retval All other values(0 included): Success, the value is handle of this TCP connection.
  */
 
 uintptr_t port_tcp_establish(const char *host, uint16_t port)
 {
     struct addrinfo hints;
     struct addrinfo *addrInfoList = NULL;
     struct addrinfo *cur = NULL;
     int fd = 0;
     int rc = 0;
     char service[6];
     uint8_t dns_retry = 0;
 
     memset(&hints, 0, sizeof(hints));
 
     printf("establish tcp connection with server(host='%s', port=[%u])\n", host, port);
 
     hints.ai_family = AF_INET; /* only IPv4 */
     hints.ai_socktype = SOCK_STREAM;
     hints.ai_protocol = IPPROTO_TCP;
     sprintf(service, "%u", port);
 
     while(dns_retry++ < 8) {
         rc = getaddrinfo(host, service, &hints, &addrInfoList);
         if (rc != 0) {
             printf("getaddrinfo error[%d], res: %s, host: %s, port: %s\n", dns_retry, gai_strerror(rc), host, service);
             sleep(1);
             continue;
         }else{
             break;
         }
     }
 
     if (rc != 0) {
         printf("getaddrinfo error(%d), host = '%s', port = [%d]\n", rc, host, port);
         return (uintptr_t)(-1);
     }
 
     for (cur = addrInfoList; cur != NULL; cur = cur->ai_next) {
         if (cur->ai_family != AF_INET) {
             printf("socket type error\n");
             rc = -1;
             continue;
         }
 
         fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
         if (fd < 0) {
             printf("create socket error\n");
             rc = -1;
             continue;
         }
 
         if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
             rc = fd;
             break;
         }
 
         close(fd);
         printf("connect error\n");
         rc = -1;
     }
 
     if (-1 == rc) {
         printf("fail to establish tcp\n");
     } else {
         printf("success to establish tcp, fd=%d\n", rc);
     }
     freeaddrinfo(addrInfoList);
 
     return (uintptr_t)rc;
 }
 
 
 
 /**
  * @brief Read data from the specific TCP connection with timeout parameter.
  *        The API will return immediately if 'len' be received from the specific TCP connection.
  *
  * @param [in] fd @n A descriptor identifying a TCP connection.
  * @param [out] buf @n A pointer to a buffer to receive incoming data.
  * @param [out] len @n The length, in bytes, of the data pointed to by the 'buf' parameter.
  * @param [in] timeout_ms @n Specify the timeout value in millisecond. In other words, the API block 'timeout_ms' millisecond maximumly.
  *
  * @retval       -2 : TCP connection error occur.
  * @retval       -1 : TCP connection be closed by remote server.
  * @retval        0 : No any data be received in 'timeout_ms' timeout period.
  * @retval (0, len] : The total number of bytes be received in 'timeout_ms' timeout period.
 
  * @see None.
  */
 
 int32_t port_tcp_read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms)
 {
     int ret, err_code, tcp_fd;
     uint32_t len_recv;
     uint64_t t_end, t_left;
     fd_set sets;
     struct timeval timeout;
 
     t_end = _linux_get_time_ms() + timeout_ms;
     len_recv = 0;
     err_code = 0;
 
     if (fd >= FD_SETSIZE) {
         return -1;
     }
     tcp_fd = (int)fd;
 
     do {
         t_left = _linux_time_left(t_end, _linux_get_time_ms());
         if (0 == t_left) {
             break;
         }
         FD_ZERO(&sets);
         FD_SET(tcp_fd, &sets);
 
         timeout.tv_sec = t_left / 1000;
         timeout.tv_usec = (t_left % 1000) * 1000;
 
         ret = select(tcp_fd + 1, &sets, NULL, NULL, &timeout);
         if (ret > 0) {
             ret = recv(tcp_fd, buf + len_recv, len - len_recv, 0);
             if (ret > 0) {
                 len_recv += ret;
             } else if (0 == ret) {
                 printf("connection is closed\n");
                 err_code = -1;
                 break;
             } else {
                 if (EINTR == errno) {
                     continue;
                 }
                 printf("recv fail\n");
                 err_code = -2;
                 break;
             }
         } else if (0 == ret) {
             break;
         } else {
             if (EINTR == errno) {
                 continue;
             }
             printf("select-recv fail\n");
             err_code = -2;
             break;
         }
     } while ((len_recv < len));
 
     /* priority to return data bytes if any data be received from TCP connection. */
     /* It will get error code on next calling */
     return (0 != len_recv) ? len_recv : err_code;
 }
 
 
 /**
  * @brief Write data into the specific TCP connection.
  *        The API will return immediately if 'len' be written into the specific TCP connection.
  *
  * @param [in] fd @n A descriptor identifying a connection.
  * @param [in] buf @n A pointer to a buffer containing the data to be transmitted.
  * @param [in] len @n The length, in bytes, of the data pointed to by the 'buf' parameter.
  * @param [in] timeout_ms @n Specify the timeout value in millisecond. In other words, the API block 'timeout_ms' millisecond maximumly.
  *
  * @retval      < 0 : TCP connection error occur..
  * @retval        0 : No any data be write into the TCP connection in 'timeout_ms' timeout period.
  * @retval (0, len] : The total number of bytes be written in 'timeout_ms' timeout period.
 
  * @see None.
  */
 
 int32_t port_tcp_write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms)
 {
     int ret,tcp_fd;
     uint32_t len_sent;
     uint64_t t_end, t_left;
     fd_set sets;
     int net_err = 0;
 
     t_end = _linux_get_time_ms() + timeout_ms;
     len_sent = 0;
     ret = 1; /* send one time if timeout_ms is value 0 */
 
     if (fd >= FD_SETSIZE) {
         return -1;
     }
     tcp_fd = (int)fd;
 
     do {
         t_left = _linux_time_left(t_end, _linux_get_time_ms());
 
         if (0 != t_left) {
             struct timeval timeout;
 
             FD_ZERO(&sets);
             FD_SET(tcp_fd, &sets);
 
             timeout.tv_sec = t_left / 1000;
             timeout.tv_usec = (t_left % 1000) * 1000;
 
             ret = select(tcp_fd + 1, NULL, &sets, NULL, &timeout);
             if (ret > 0) {
                 if (0 == FD_ISSET(tcp_fd, &sets)) {
                     printf("Should NOT arrive\n");
                     /* If timeout in next loop, it will not sent any data */
                     ret = 0;
                     continue;
                 }
             } else if (0 == ret) {
                 printf("select-write timeout %d\n", tcp_fd);
                 break;
             } else {
                 if (EINTR == errno) {
                     printf("EINTR be caught\n");
                     continue;
                 }
 
                 printf("select-write fail, ret = select() = %d\n", ret);
                 net_err = 1;
                 break;
             }
         }
 
         if (ret > 0) {
             ret = send(tcp_fd, buf + len_sent, len - len_sent, 0);
             if (ret > 0) {
                 len_sent += ret;
             } else if (0 == ret) {
                 printf("No data be sent\n");
             } else {
                 if (EINTR == errno) {
                     printf("EINTR be caught\n");
                     continue;
                 }
 
                 printf("send fail, ret = send() = %d\n", ret);
                 net_err = 1;
                 break;
             }
         }
     } while (!net_err && (len_sent < len) && (_linux_time_left(t_end, _linux_get_time_ms()) > 0));
 
     if (net_err) {
         return -1;
     } else {
         return len_sent;
     }
 }