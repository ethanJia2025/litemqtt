#ifndef __MQTT_CLIENT_PRIVATE_H__
#define __MQTT_CLIENT_PRIVATE_H__

#include <stdint.h>
#include "utils_timer.h"
#include "utils_net.h"
#include "MQTTPacket.h"
#include "mqtt_client.h"
#include "mqtt_client_config.h"
#include "cQueue.h"
#include "uthash.h"
 

#define mqtt_malloc(size)                       port_malloc(size)
#define mqtt_free(ptr)                          {port_free((void *)ptr);ptr = NULL;}

 #define MQTT_DYNBUF_SEND_MARGIN                      (64)
 #define MQTT_DYNBUF_RECV_MARGIN                      (8)

 /* maximum MQTT packet-id */
#define MQTT_PACKET_ID_MAX                            (65535)

 typedef enum {
    MC_CONNECTION_ACCEPTED = 0,
    MC_CONNECTION_REFUSED_UNACCEPTABLE_PROTOCOL_VERSION = 1,
    MC_CONNECTION_REFUSED_IDENTIFIER_REJECTED = 2,
    MC_CONNECTION_REFUSED_SERVER_UNAVAILABLE = 3,
    MC_CONNECTION_REFUSED_BAD_USERDATA = 4,
    MC_CONNECTION_REFUSED_NOT_AUTHORIZED = 5
} iotx_mc_connect_ack_code_t;

 typedef enum {
    MC_STATE_INVALID = 0,                    /* MQTT in invalid state */
    MC_STATE_INITIALIZED = 1,                /* MQTT in initializing state */
    MC_STATE_CONNECTED = 2,                  /* MQTT in connected state */
    MC_STATE_DISCONNECTED = 3,               /* MQTT in disconnected state */
    MC_STATE_DISCONNECTED_RECONNECTING = 4,  /* MQTT in reconnecting state */
    MC_STATE_CONNECT_BLOCK = 5,              /* MQTT in connecting state when using async protocol stack */
} mc_state_t;

/* Reconnected parameter of MQTT client */
typedef struct {
    utils_time_t         reconnect_next_time;        /* the next time point of reconnect */
    uint32_t            reconnect_time_interval_ms; /* time interval of this reconnect */
} mc_reconnect_param_t;



typedef struct{
    int                 packet_id;              // 定义为int类型，因为uthash的int key，对类型敏感，不能为u16
    uint32_t            len;
    unsigned char       *buf;
    utils_time_t        pub_start_time;
    uint16_t            repub_cnt;
    UT_hash_handle      hh;             // uthash需要用到的哈希表句柄
} mqtt_qos1_msg_hashmap_node_t;


typedef struct{
    char                               *topic_name;   
    unsigned short                      packet_id; 
    mqtt_qos_t                          qos;
    mqtt_client_sub_msg_notify_cb       topic_callback;
    void                               *cb_param;
    utils_time_t                        sub_start_time;
    unsigned char                       sub_succ;
    UT_hash_handle      hh;
} mqtt_subscribe_hashmap_node_t;


typedef struct{
    char *topic_name;
} mqtt_unsub_info_t;


typedef enum{
    MC_JOB_TYPE_PUBLISH,
    MC_JOB_TYPE_SUB_MSG_NOTIFY,
    MC_JOB_TYPE_UNSUB,
    MC_JOB_TYPE_CONN_EVENT_NOTIFY,
    MC_JOB_TYPE_ATTEMPT_DISCONNECTING,
    MC_JOB_TYPE_DESTROY_CLIENT,
} mqtt_client_rte_job_type_t;


typedef struct{
    mqtt_client_rte_job_type_t      job_type;
    // 根据job type定义共同体数据结构
    union{
        mqtt_topic_info_t           *topic_info;
        char                        *unsub_topic_name;
        mqtt_client_conn_event_e     conn_event;
        void                         *param;
    };
} mqtt_client_rte_job_info_t;


/* structure of MQTT client */
typedef struct _Client {
    void                                *lock_generic;                               /* generic lock */
    uint32_t                            packet_id;                                  /* packet id */
    uint32_t                            request_timeout_ms;                         /* request timeout in millisecond */
    uint32_t                            cycle_timeout_ms;
    uint32_t                            buf_size_send;                              /* send buffer size in byte */

    uint32_t                            buf_size_send_max;                          /* send buffer size max limit in byte */
    uint32_t                            buf_size_read_max;                          /* recv buffer size max limit in byte */

    uint8_t                             keepalive_probes;                           /* keepalive probes */
    char                                *buf_send;                                   /* pointer of send buffer */
    char                                *buf_read;                                   /* pointer of read buffer */
    uint32_t                            buf_size_read;                              /* read buffer size in byte */
    cQueue_t                            *rte_job_queue;                             /* publish cache queue */
   
    mqtt_qos1_msg_hashmap_node_t        *qos1_msg_hashmap_table;
    mqtt_subscribe_hashmap_node_t       *subscribe_hashmap_table;

    utils_network_t                     ipstack;                                    /* network parameter */
    utils_time_t                        next_ping_time;                             /* next ping time */
    mc_state_t                          client_state;                               /* state of MQTT client */
    mc_reconnect_param_t                reconnect_param;                            /* reconnect parameter */
    MQTTPacket_connectData              connect_data;                               /* connection parameter */
 
    char                                *buf_host_name;                             /* host name */
    char                                *buf_clientId;                              /* client id */
    char                                *buf_username;                              /* user name */
    char                                *buf_password;                              /* password */

    mqtt_client_conn_event_e                    curr_conn_state;
    mqtt_client_conn_event_notify_cb            conn_event_notify_cb;                   // connect result notify callback
    void                                        *conn_event_notify_cb_param;            // connect result notify callback param


} mc_client_t, *mc_client_pt;
 





/** log level 为 none */
#if CONFIG_MQTT_LOG_LEVEL == 0
#define mqtt_err(...)               
#define mqtt_warning(...)           
#define mqtt_info(...)              
#define mqtt_debug(...)     
/** log level 为 err */        
#elif   CONFIG_MQTT_LOG_LEVEL == 1
#define mqtt_err(...)               do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_warning(...)           
#define mqtt_info(...)              
#define mqtt_debug(...)             
#elif   CONFIG_MQTT_LOG_LEVEL == 2             
#define mqtt_err(...)               do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_warning(...)           do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_info(...)              
#define mqtt_debug(...)             
#elif   CONFIG_MQTT_LOG_LEVEL == 3
#define mqtt_err(...)               do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_warning(...)           do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_info(...)              do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_debug(...)             
#else
#define mqtt_err(...)               do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_warning(...)           do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_info(...)              do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#define mqtt_debug(...)             do{port_printf(__VA_ARGS__);port_printf("\r\n");}while(0)
#endif








 
 #endif  /* __MQTT_CLIENT_PRIVATE_H__ */
 
 
 