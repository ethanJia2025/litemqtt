/*
 * Copyright © jsq <jsq234@163.com>
 *
 * 
 *
 */


#ifndef __MQTT_CLIENT_H
#define __MQTT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _Client mqtt_client_t;


/**
 * @brief MQTT QoS等级定义
 */
typedef enum {
    MQTT_QOS0 = 0,
    MQTT_QOS1,
} mqtt_qos_t;


/**
 * @brief MQTT topic信息定义
 */
typedef struct{
    unsigned short packet_id;       // MQTT消息包ID
    mqtt_qos_t  qos;                // MQTT消息QoS等级
    unsigned char dup;              // 是否重复发送
    unsigned char retain;           // 是否保留消息
    char *topic_name;               // 主题名称
    unsigned int payload_len;       // 消息数据长度
    unsigned char *payload;         // 消息数据
} mqtt_topic_info_t;


/**
 * @brief MQTT客户端连接事件定义
 */
typedef enum{
    MC_CONN_EVENT_CONNECTED = 1,        // 连接成功
    MC_CONN_EVENT_DISCONNECTED,         // 断开连接
} mqtt_client_conn_event_e;


/**
 * @brief MQTT客户端订阅消息通知回调定义
 * 
 * @param pclient MQTT客户端句柄
 * @param topic_info 订阅消息信息
 * @param cb_param 用户自定义参数
 * @return void
 */
typedef void (*mqtt_client_sub_msg_notify_cb)(mqtt_client_t *pclient, 
                                        mqtt_topic_info_t *topic_info,
                                        void *cb_param);

/**
 * @brief MQTT客户端连接事件通知回调定义
 * 
 * @param pclient MQTT客户端句柄    
 * @param result 连接结果
 * @param cb_param 用户自定义参数
 * 
 * @note 该回调函数在MQTT客户端连接成功或断开时被调用
 */
typedef void (*mqtt_client_conn_event_notify_cb)(mqtt_client_t *pclient, mqtt_client_conn_event_e result, void *cb_param);


/**
 * @brief 设置MQTT客户端连接事件通知回调
 * 
 * @param pclient MQTT客户端句柄
 * @param notify_cb 连接事件通知回调函数
 * @param cb_param 用户自定义参数
 * 
 * @return int 0:成功，其他:失败
 * 
 * @note 调用者只有调用该函数后，才能收到MQTT客户端连接成功或断开的通知
 * @note 该函数必须在mqtt_client_connect()之前调用
 */
int mqtt_client_set_conn_event_notify_cb(mqtt_client_t *pclient, mqtt_client_conn_event_notify_cb notify_cb, void *cb_param);


/**
 * @brief MQTT客户端连接安全模式定义
 */
typedef enum {
    MQTT_SEC_NONE = 0,              // 不使用安全连接
    MQTT_SEC_SSL_SERVER_AUTH,       // 使用SSL/TLS连接，服务器端验证
    MQTT_SEC_SSL_MUTUAL_AUTH,       // 使用SSL/TLS连接，双向验证
} mqtt_security_mode_t;

/**
 * @brief MQTT客户端连接配置
 */
typedef struct{
    const char              *host;                      // 服务器地址
    unsigned short          port;                       // 服务器端口
    const char              *client_id;                 // 客户端ID
    const char              *username;                  // 用户名
    const char              *password;                  // 密码
    int                     keep_alive_interval_ms;     // 心跳间隔
    mqtt_security_mode_t    security_mode;              // 安全连接模式
} mqtt_conn_config_t;


/**
 * @brief MQTT客户端TLS参数配置
 * 
 * @note 该结构体仅在MQTT_SEC_SSL_SERVER_AUTH和MQTT_SEC_SSL_MUTUAL_AUTH模式下有效
 * 
 * @note !!!特别注意：由于安全和内存资源使用考虑，比如在RTOS平台上，CA证书可能会占用4KB，为了避免内存使用浪费，
 *       mqtt client内部不再深拷贝拷贝tls证书等数据，所以APP传入tls_config参数后，不能够释放对应的证书数据内存。
 * 
 */
typedef struct {
    const char *ca_cert;            // CA证书
    const char *client_cert;        // 客户端证书
    const char *client_key;         // 客户端私钥
    const char *client_key_pwd;     // 客户端私钥密码
} mqtt_tls_config_t;


/**
 * @brief 创建一个MQTT客户端
 * @param conn 连接配置
 * @param tls_config TLS配置
 * @return mqtt_client_t* MQTT客户端句柄
 * 
 * @note 1. 当conn->security_mode为MQTT_SEC_NONE时，tls_config参数无效,可以传入NULL
 * 
 */
mqtt_client_t *mqtt_client_new(mqtt_conn_config_t *conn, mqtt_tls_config_t *tls_config);


/**
 * @brief 启动MQTT连接
 * @param pclient MQTT客户端句柄
 * 
 * @return int 0:成功，其他:失败
 * 
 * @note 1. 该函数会阻塞，直到连接成功或失败
 */
int mqtt_client_connect(mqtt_client_t *pclient);


/**
 * @brief 断开MQTT连接
 * @param pclient MQTT客户端句柄
 * 
 * @return int 0:成功，其他:失败
 * 
 * @note 1. 该函数为异步函数，调用后立即返回，会先将未发送的数据发送到服务器，然后将断开请求发送到MQTT服务器
 */
int mqtt_client_disconnect(mqtt_client_t *pclient);

/**
 * @brief mqtt client 轮询，处理接收消息，发送心跳等
 * @param pclient       MQTT客户端句柄
 * @param timeout_ms    超时轮询时间，单位毫秒
 * @return int 0:成功，其他:失败
 * 
 * @note 该函数需要定时调用，以保证MQTT客户端正常工作，建议在独立的线程/任务中调用
 */
int mqtt_client_poll(mqtt_client_t *pclient, int timeout_ms);


/**
 * @brief mqtt client 订阅消息
 * 
 * @param pclient MQTT客户端句柄
 * @param topic_name 订阅的主题名称
 * @param qos 订阅的QoS等级,目前仅支持MQTT_QOS0和MQTT_QOS1
 * @param topic_callback 订阅消息通知回调函数
 * @param cb_param 用户自定义参数
 * 
 * @return int 0:成功，其他:失败
 * 
 * @note 1. 该函数为异步函数，调用后立即返回，内部会自动处理订阅请求。
 *       2. 如果在mqtt_client_config.h中配置CONFIG_SUPPORT_RECONNECTED_AUTO_RESUBSCRIBE为1，则订阅失败时，会自动重试订阅
 *  
 */
int mqtt_client_subscribe(mqtt_client_t *pclient,
                const char *topic_name,
                mqtt_qos_t qos,
                mqtt_client_sub_msg_notify_cb topic_callback,
                void *cb_param);

/**
 * @brief mqtt client 取消订阅
 * 
 * @param pclient MQTT客户端句柄
 * @param topic_name 取消订阅的主题名称
 * 
 */
int mqtt_client_unsubscribe(mqtt_client_t *pclient, const char *topic_name);

/**
 * @brief mqtt client 发布消息
 * 
 * @param pclient MQTT客户端句柄
 * @param topic_name 发布的主题名称
 * @param qos 发布的QoS等级,目前仅支持MQTT_QOS0和MQTT_QOS1
 * @param data 发布的消息数据
 * @param len 发布的消息数据长度
 * 
 * @return int 0:成功，其他:失败
 * 
 * @note 1. 该函数为异步函数，调用后立即返回，内部会自动处理发布请求。
 */
int mqtt_client_publish(mqtt_client_t *pclient, 
                const char *topic_name, 
                mqtt_qos_t qos, 
                unsigned char *data, 
                int len);


#ifdef __cplusplus
}
#endif
#endif