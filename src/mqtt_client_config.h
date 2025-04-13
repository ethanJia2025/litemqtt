#ifndef _MQTT_CLIENT_CONFIG_H_
#define _MQTT_CLIENT_CONFIG_H_


/**
 * @brief Maximum size of the MQTT send buffer.
 * @details This macro defines the maximum size in bytes 
 *          for the buffer used when sending MQTT messages.
 *          
 * @note MQTT 发送缓冲区的最大大小。
 *       该宏定义了发送 MQTT 消息时使用的缓冲区的最大字节数
 */
#define CONFIG_MQTT_BUFFER_SEND_MAX                     (10*1024)


/**
 * @brief Defines the maximum size of the MQTT read buffer in bytes.
 *        This buffer is used to store incoming MQTT messages.
 *       
 *
 * 定义 MQTT 读取缓冲区的最大大小（以字节为单位）。
 * 此缓冲区用于存储接收的 MQTT 消息。
 */
#define CONFIG_MQTT_BUFFER_READ_MAX                     (5*1024)


/**
 * @brief CONFIG_MQTT_REQUEST_TIMEOUT defines the timeout duration for MQTT requests.
 * 
 * This macro specifies the maximum time, in milliseconds, that the client will wait 
 * for a response to an MQTT request before considering it as timed out.
 * 
 * 该宏定义了MQTT请求的超时时间。
 * 它以毫秒为单位指定客户端在将MQTT请求视为超时之前等待响应的最长时间。
 */
#define CONFIG_MQTT_REQUEST_TIMEOUT                     (1000)



/**
 * @brief Minimum interval in milliseconds for MQTT client to attempt reconnection.
 *        MQTT客户端尝试重新连接的最小时间间隔（以毫秒为单位）。
 *
 * This macro defines the minimum time the MQTT client will wait before attempting
 * to reconnect to the server after a disconnection. It helps to prevent excessive
 * reconnection attempts in a short period of time.
 * 该宏定义了MQTT客户端在断开连接后尝试重新连接服务器之前等待的最短时间。
 * 它有助于防止在短时间内过多的重新连接尝试。
 */
#define CONFIG_MQTT_RECONNECT_INTERVAL_MIN_MS           (2000)

/**
 * @brief Maximum interval in milliseconds for MQTT client reconnection attempts.
 * 
 * This macro defines the upper limit for the time interval between 
 * reconnection attempts made by the MQTT client. It ensures that the 
 * client does not exceed this duration when retrying to establish a 
 * connection after a disconnection.
 * 
 * 该宏定义了 MQTT 客户端重连尝试的最大时间间隔（以毫秒为单位）。
 * 它确保客户端在断开连接后重新尝试建立连接时，不会超过此时间间隔。
 */
#define CONFIG_MQTT_RECONNECT_INTERVAL_MAX_MS           (60000)


/**
 * @brief Defines the MQTT keep-alive interval in seconds.
 * 
 * This macro specifies the time interval, in seconds, that the client
 * will wait before sending a PINGREQ message to the MQTT broker to
 * maintain the connection alive. It ensures that the connection is
 * not dropped due to inactivity.
 * 
 * 定义 MQTT 保持活动间隔（单位：秒）。
 * 
 * 该宏指定客户端在发送 PINGREQ 消息到 MQTT 代理以保持连接活跃之前
 * 等待的时间间隔（以秒为单位）。它确保连接不会因不活动而断开。
 * 
 * @note Adjust this value based on your application's requirements
 *       and the broker's configuration.
 */
#define CONFIG_MQTT_KEEPALIVE_INTERVAL                      (30)

/**
 * @brief Minimum keep-alive interval for MQTT connections, in seconds.
 * 
 * This macro defines the minimum allowable value for the MQTT keep-alive 
 * interval. The keep-alive interval is the maximum time interval that is 
 * permitted to elapse between the client and server communication. If no 
 * communication occurs within this interval, the client will send a 
 * PINGREQ message to the server to keep the connection alive.
 * 
 * MQTT连接的最小保活时间间隔（单位：秒）。
 * 该宏定义了MQTT保活时间间隔的最小允许值。保活时间间隔是客户端与服务器之间
 * 通信允许的最长时间间隔。如果在此时间间隔内没有通信发生，客户端将向服务器
 * 发送PINGREQ消息以保持连接。
 */
#define CONFIG_MQTT_KEEPALIVE_INTERVAL_MIN      (5)


/**
 * @brief Defines the maximum keep-alive interval for the MQTT client in seconds.
 *        This value specifies the maximum duration the client can wait without
 *        sending a PINGREQ message to the server to maintain the connection alive.
 *        It ensures the connection remains active even during periods of inactivity.
 *
 * @note The value is set to 1200 seconds (20 minutes) by default.
 *
 * @中文说明:
 * @brief 定义MQTT客户端的最大保活时间间隔（单位：秒）。
 *        该值指定客户端在不向服务器发送PINGREQ消息的情况下，
 *        保持连接存活的最长时间。它确保即使在空闲期间，连接仍然保持活跃。
 *
 * @注意: 默认值为1200秒（20分钟）。
 */
#define CONFIG_MQTT_KEEPALIVE_INTERVAL_MAX      (1200)


/**
 * @brief CONFIG_MQTT_ONLY_SUPPORT_QOS0
 * 
 * This macro defines whether the MQTT client only supports QoS level 0.
 * 
 * Value:
 * - 0: The MQTT client may support other QoS levels (e.g., QoS 1).
 * - 1: The MQTT client is restricted to only supporting QoS level 0.
 * 
 * Quality of Service (QoS) levels in MQTT:
 * - QoS 0: At most once delivery (fire-and-forget).
 * - QoS 1: At least once delivery.
 * - QoS 2: Exactly once delivery.
 * 
 * Note: QoS 0 is the simplest and most lightweight level, suitable for 
 * scenarios where message delivery guarantees are not critical.
 * 
 * 该宏定义用于配置 MQTT 客户端是否仅支持 QoS 等级 0。
 * 
 * 值说明：
 * - 0：MQTT 客户端可能支持其他 QoS 等级（例如 QoS 1）。
 * - 1：MQTT 客户端仅支持 QoS 等级 0。
 * 
 * MQTT 的服务质量（QoS）等级：
 * - QoS 0：最多一次传递（即发即弃）。
 * - QoS 1：至少一次传递。
 * - QoS 2：精确一次传递（暂不支持）
 * 
 * 注意：QoS 0 是最简单且最轻量级的等级，适用于对消息传递可靠性要求不高的场景。
 */
#define CONFIG_MQTT_ONLY_SUPPORT_QOS0                       (0)


/**
 * @brief Defines the maximum number of topics that can be subscribed to simultaneously.
 *        This macro sets an upper limit for multi-subscription functionality in the MQTT client.
 * 
 * 定义可以同时订阅的主题的最大数量。
 * 该宏为 MQTT 客户端的多订阅功能设置了上限。
 * 
 * @note Adjust this value based on the application's requirements and memory constraints.
 *       根据应用需求和内存限制调整此值。
 */
#define CONFIG_MQTT_MUTLI_SUBSCRIBE_MAX                     (5)


/**
 * @brief Defines the MQTT protocol version to be used by the client.
 *        设置客户端使用的MQTT协议版本。
 *
 * @details This macro specifies the MQTT protocol version. The value (4) corresponds
 *          to MQTT version 3.1.1, which is widely used and supported. Ensure that
 *          the broker you are connecting to supports this version.
 *          此宏定义了MQTT协议版本。值 (4) 对应于MQTT版本3.1.1，这是广泛使用和支持的版本。
 *          请确保您连接的代理支持此版本。
 */
#define CONFIG_MQTT_VERSION                                 (4)



/**
 * @brief Maximum number of consecutive keep-alive probes without acknowledgment
 *        before the MQTT client considers the connection abnormal and initiates
 *        an automatic reconnection.
 *
 * 该宏定义了在没有收到心跳ACK的情况下，MQTT客户端连续发送的最大探测次数。
 * 如果超过该次数仍未收到ACK，则判定当前连接异常，MQTT客户端会自动断开并尝试重连。
 *
 * @note A lower value may result in quicker detection of connection issues,
 *       while a higher value may tolerate temporary network instability.
 *
 * @注意 较低的值可能会更快检测到连接问题，而较高的值可能会容忍临时的网络不稳定。
 */
#define CONFIG_MQTT_KEEPALIVE_PROBES_MAX                    (2)



/**
 * @brief Enables or disables automatic re-subscription to previously subscribed topics 
 *        after the MQTT client reconnects.
 * 
 * 当MQTT客户端断开连接并重新连接后，是否自动重新订阅之前已订阅的主题。
 * 
 * - Set to 1 (enabled): The client will automatically re-subscribe to all topics 
 *   that were subscribed to before the disconnection.
 *   设置为1（启用）：客户端将在重新连接后自动重新订阅所有之前订阅的主题。
 * 
 * - Set to 0 (disabled): The client will not automatically re-subscribe to any topics 
 *   after reconnecting.
 *   设置为0（禁用）：客户端在重新连接后不会自动重新订阅任何主题。
 */
#define CONFIG_SUPPORT_RECONNECTED_AUTO_RESUBSCRIBE         (1)



/**
 * @brief Defines the maximum length of the MQTT publish send queue.
 *        This macro specifies the size of the internal buffer queue
 *        used by the MQTT client to temporarily store messages published
 *        by the application before they are sent.
 *
 * @note Increasing this value allows the application to queue more
 *       messages for publishing, but it may also increase memory usage.
 *
 * @注意 定义MQTT发布发送队列的最大长度。
 *       该宏指定MQTT客户端内部缓冲队列的大小，用于暂存应用程序发布的消息，
 *       然后再进行发送。
 *
 * @提示 增大该值可以允许应用程序排队更多的发布消息，但可能会增加内存使用。
 */
#define CONFIG_MQTT_PUB_CACHE_QUEUE_SIZE                    (100)

/**
 * @brief 配置MQTT Client日志级别
 * 
 * This macro defines the log level for the MQTT client. The log level determines
 * the verbosity of the logs generated by the MQTT client. The supported levels are:
 * 
 * - 0: none    - No logs will be generated.
 * - 1: error   - Only error messages will be logged.
 * - 2: warning - Warnings and error messages will be logged.
 * - 3: info    - Informational messages, warnings, and errors will be logged.
 * - 4: debug   - Debug messages, informational messages, warnings, and errors will be logged.
 * 
 * @note 设置日志级别时，请根据实际需求选择合适的级别，以平衡日志信息的详细程度和性能开销。
 */
#define CONFIG_MQTT_LOG_LEVEL                               (4)


/**
 * @brief CONFIG_SUPPORT_TLS 宏定义用于配置 MQTT 客户端是否支持 TLS/SSL（即 MQTT over SSL/TLS，简称 MQTTs）。
 * 
 * @details
 * - 如果该宏定义为 1，则表示支持 TLS/SSL，启用安全的 MQTTs 通信。
 * - 如果该宏定义为 0，则表示不支持 TLS/SSL，仅支持非加密的 MQTT 通信。
 * 
 * This macro defines whether the MQTT client supports TLS/SSL (i.e., MQTT over SSL/TLS, also known as MQTTs).
 * 
 * - If set to 1, TLS/SSL is supported, enabling secure MQTTs communication.
 * - If set to 0, TLS/SSL is not supported, and only unencrypted MQTT communication is available.
 */
//#define CONFIG_SUPPORT_TLS                              


#endif
