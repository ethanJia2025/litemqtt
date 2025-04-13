#include "mqtt_client.h"
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "port.h"
#include "mqtt_client_err_code.h"
#include "utils_timer.h"
#include "mqtt_client_private.h"
#include "MQTTPacket.h"
#include "mqtt_client_config.h"

static int mc_run_rte_job_conn_event_notify(mqtt_client_t *pclient, mqtt_client_conn_event_e event)
{
    mqtt_client_rte_job_info_t *job_info;

    if(pclient == NULL){
        mqtt_err("param is null.");
        return NULL_VALUE_ERROR;
    }

    // 创建解订阅 rte job
    job_info = (mqtt_client_rte_job_info_t *)mqtt_malloc(sizeof(mqtt_client_rte_job_info_t));
    if(job_info == NULL){
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }

    job_info->job_type = MC_JOB_TYPE_CONN_EVENT_NOTIFY;
    job_info->conn_event = event;

    cQPost(pclient->rte_job_queue, (void *)job_info);

    return SUCCESS_RETURN;
    
}

static void mc_reset_subcribe_hashmap_sub_state(mqtt_client_t *pclient)
{
    if(pclient == NULL){
        return;
    }

    if(pclient->subscribe_hashmap_table != NULL){
        mqtt_subscribe_hashmap_node_t *node, *node_next;
        // 遍历订阅哈希表,将所有节点的sub_succ标志位设置为0
        HASH_ITER(hh, pclient->subscribe_hashmap_table, node, node_next) {
            node->sub_succ = 0;
        }
    }
}


static void mc_subscribe_hashmap_clear(mqtt_client_t *pclient)
{
    mqtt_subscribe_hashmap_node_t *node, *node_next;

    if(pclient == NULL){
        return;
    }

    // 遍历订阅哈希表,删除所有节点并释放内存
    HASH_ITER(hh, pclient->subscribe_hashmap_table, node, node_next) {
        HASH_DEL(pclient->subscribe_hashmap_table, node);
        if(node->topic_name){
            mqtt_free(node->topic_name);
        }
        mqtt_free(node);
    }

    pclient->subscribe_hashmap_table = NULL;
}




static int mc_set_client_state(mqtt_client_t *pclient, mc_state_t new_state)
{
    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    port_mutex_lock(pclient->lock_generic);
    pclient->client_state = new_state;

    if(new_state == MC_STATE_CONNECTED){
        if(pclient->curr_conn_state != MC_CONN_EVENT_CONNECTED){
            mc_run_rte_job_conn_event_notify(pclient, MC_CONN_EVENT_CONNECTED);
            pclient->curr_conn_state = MC_CONN_EVENT_CONNECTED;
        }
    }else if(new_state == MC_STATE_DISCONNECTED){
        if(pclient->curr_conn_state != MC_CONN_EVENT_DISCONNECTED){

#if CONFIG_SUPPORT_RECONNECTED_AUTO_RESUBSCRIBE
            mc_reset_subcribe_hashmap_sub_state(pclient);
#else
            mc_subscribe_hashmap_clear(pclient);
#endif
            // 触发断开通知事件
            mc_run_rte_job_conn_event_notify(pclient, MC_CONN_EVENT_DISCONNECTED);
            pclient->curr_conn_state = MC_CONN_EVENT_DISCONNECTED;
        }
    }

    port_mutex_unlock(pclient->lock_generic);

    return SUCCESS_RETURN;
}

static mc_state_t mc_get_client_state(mqtt_client_t *pclient)
{
    mc_state_t state = MC_STATE_INVALID;

    if (NULL == pclient) {
        return MC_STATE_INVALID;
    }

    port_mutex_lock(pclient->lock_generic);
    state = pclient->client_state;
    port_mutex_unlock(pclient->lock_generic);

    return state;
}





/**
 * @brief 校验 MQTT Topic 名称合法性（支持发布/订阅场景）
 * @param topic     待校验的 Topic 字符串
 * @param is_publish true-发布场景，false-订阅场景
 * @return true-合法，false-非法
 */
static int mc_check_topic_name(const char* topic, uint8_t is_publish) 
{
    size_t len = strlen(topic);
    
    // 基础检查：空值、长度、保留前缀
    if (len == 0 || len > 65535) {
        return -1;
    }
    
    // 遍历字符检查
    for (size_t i = 0; i < len; i++) {
        unsigned char c = topic[i];
        
        // 通用非法字符：非可打印字符
        if (!isprint(c)) return -1;
        
        // 场景相关校验
        if (is_publish) {
            // 发布场景：禁止所有通配符
            if (c == '#' || c == '+') return -1;
        } else {
            // 订阅场景：允许通配符但需校验位置
            if (c == '#') {
                // # 必须为末字符且前有层级分隔符（如 "a/#" 合法，"a#b" 非法）
                if (i != len - 1 || (i > 0 && topic[i-1] != '/')) return -1;
            } else if (c == '+') {
                // + 必须被层级分隔符包围（如 "a/+/b" 合法，"a+b" 非法）
                if ((i > 0 && topic[i-1] != '/') || (i < len-1 && topic[i+1] != '/')) {
                    return -1;
                }
            }
        }
    }
    return 0;
}



static int mc_get_next_packet_id(mqtt_client_t *pclient)
{
    unsigned int id = 0;

    if (!pclient) {
        return FAIL_RETURN;
    }

    pclient->packet_id = (pclient->packet_id == MQTT_PACKET_ID_MAX) ? 1 : pclient->packet_id + 1;
    id = pclient->packet_id;
   
    return id;
}


static void mqtt_conn_data_common_init(MQTTPacket_connectData *connectdata, 
                                    int mqtt_version)
{
    connectdata->struct_id[0] = 'M';
    connectdata->struct_id[1] = 'Q';
    connectdata->struct_id[2] = 'T';
    connectdata->struct_id[3] = 'C';

    connectdata->struct_version = 0;
    /** Version of MQTT to be used.  3 = 3.1 4 = 3.1.1
      */
    connectdata->MQTTVersion = mqtt_version;

    connectdata->will.struct_id[0] = 'M';
    connectdata->will.struct_id[1] = 'Q';
    connectdata->will.struct_id[2] = 'T';
    connectdata->will.struct_id[3] = 'W';

    connectdata->will.struct_version = 0;
    connectdata->willFlag = 0;
    connectdata->cleansession = 0;
}



// 初始化mqtt client
static int mqtt_client_init(mqtt_client_t *pclient, const mqtt_conn_config_t *conn, const mqtt_tls_config_t *tls_config)
{
    int rc = FAIL_RETURN;
    mc_state_t mc_state = MC_STATE_INVALID;
    int len_tmp;
    MQTTPacket_connectData *connectdata = NULL;

    if (NULL == pclient || NULL == conn ||
        NULL == conn->client_id) {
        return NULL_VALUE_ERROR;
    }

    // pub发送消息缓存队列初始化
    pclient->rte_job_queue = cQcreate(CONFIG_MQTT_PUB_CACHE_QUEUE_SIZE);
    if(NULL == pclient->rte_job_queue){
        mqtt_err("malloc rte job queue failed\n");
        return FAIL_RETURN;
    }

    // qos1 消息hashmap初始化
    pclient->qos1_msg_hashmap_table = NULL;
    // sub hashmap初始化
    pclient->subscribe_hashmap_table = NULL;


    // 初始化连接配置
    connectdata = &(pclient->connect_data);

    pclient->lock_generic = port_mutex_create();

    // request timerout
    pclient->request_timeout_ms = CONFIG_MQTT_REQUEST_TIMEOUT;

    pclient->buf_size_send_max = CONFIG_MQTT_BUFFER_SEND_MAX;
    pclient->buf_size_read_max = CONFIG_MQTT_BUFFER_READ_MAX;

    pclient->keepalive_probes = 0;

    pclient->reconnect_param.reconnect_time_interval_ms = CONFIG_MQTT_RECONNECT_INTERVAL_MIN_MS;

    // 初始化连接数据
    mqtt_conn_data_common_init(connectdata, CONFIG_MQTT_VERSION);
    // client id
    len_tmp = strlen(conn->client_id);
    pclient->buf_clientId = port_malloc(len_tmp + 1);
    if (NULL == pclient->buf_clientId) {
        port_printf("malloc buf_clientId failed\n");
        goto RETURN;
    }
    memset(pclient->buf_clientId, 0, len_tmp + 1);
    strncpy(pclient->buf_clientId, conn->client_id, len_tmp);
    connectdata->clientID.cstring = pclient->buf_clientId;
    // username
    if (NULL != conn->username) {
        len_tmp = strlen(conn->username);
        pclient->buf_username = port_malloc(len_tmp + 1);
        if (NULL == pclient->buf_username) {
            port_printf("malloc buf_username failed\n");
            goto RETURN;
        }
        memset(pclient->buf_username, 0, len_tmp + 1);
        strncpy(pclient->buf_username, conn->username, len_tmp);
        connectdata->username.cstring = pclient->buf_username;
    }
    // password
    if (NULL != conn->password) {
        len_tmp = strlen(conn->password);
        pclient->buf_password = port_malloc(len_tmp + 1);
        if (NULL == pclient->buf_password) {
            port_printf("malloc buf_password failed\n");
            goto RETURN;
        }
        memset(pclient->buf_password, 0, len_tmp + 1);
        strncpy(pclient->buf_password, conn->password, len_tmp);
        connectdata->password.cstring = pclient->buf_password;
    }

    // keepaliver interval
    connectdata->keepAliveInterval = CONFIG_MQTT_KEEPALIVE_INTERVAL;

    // 初始化timer
    utils_time_init(&pclient->next_ping_time);
    utils_time_init(&pclient->reconnect_param.reconnect_next_time);

    // network 初始化
    memset(&pclient->ipstack, 0, sizeof(utils_network_t));
    // host
    len_tmp = strlen(conn->host);
    pclient->buf_host_name = port_malloc(len_tmp + 1);
    if (NULL == pclient->buf_host_name) {
        port_printf("malloc buf_host_name failed\n");
        goto RETURN;
    }

    memset(pclient->buf_host_name, 0, len_tmp + 1);
    strncpy(pclient->buf_host_name, conn->host, len_tmp);
    pclient->ipstack.pHostAddress = pclient->buf_host_name;
    // port
    pclient->ipstack.port = conn->port;

#ifdef CONFIG_SUPPORT_TLS
    rc = utils_net_init(&pclient->ipstack, pclient->buf_host_name, pclient->ipstack.port, 
                        tls_config->ca_cert, tls_config->client_cert, tls_config->client_key, 
                        tls_config->client_key_pwd, NULL);
#else
    rc = utils_net_init(&pclient->ipstack, pclient->buf_host_name, pclient->ipstack.port, 
                        NULL, NULL, NULL, NULL, NULL);
#endif
    if (rc != SUCCESS_RETURN) {
        mc_state = MC_STATE_INVALID;
        port_printf("utils_net_init failed\n");
        goto RETURN;
    }
    mc_state = MC_STATE_INITIALIZED;
    rc = SUCCESS_RETURN;

RETURN:

    mc_set_client_state(pclient, mc_state);
    if(rc != SUCCESS_RETURN){
        if(pclient->buf_send != NULL){
            port_free(pclient->buf_send);
            pclient->buf_send = NULL;
        }
        
        if(pclient->buf_read != NULL){
            port_free(pclient->buf_read);
            pclient->buf_read = NULL;
        }

        if(pclient->buf_clientId != NULL){
            port_free(pclient->buf_clientId);
            pclient->buf_clientId = NULL;
        }

        if(pclient->buf_username != NULL){
            port_free(pclient->buf_username);
            pclient->buf_username = NULL;
        }

        if(pclient->buf_password != NULL){
            port_free(pclient->buf_password);
            pclient->buf_password = NULL;
        }

        if(pclient->buf_host_name != NULL){
            port_free(pclient->buf_host_name);
            pclient->buf_host_name = NULL;
        }

        if(pclient->lock_generic != NULL){
            port_mutex_destroy(pclient->lock_generic);
            pclient->lock_generic = NULL;
        }

#ifdef CONFIG_SUPPORT_TLS
        // TODO
#endif
    }

    return rc;
}


mqtt_client_t *mqtt_client_new(mqtt_conn_config_t *conn, mqtt_tls_config_t *tls_config)
{
    int rc = FAIL_RETURN;
    mqtt_client_t *pclient = port_malloc(sizeof(mqtt_client_t));
    if (NULL == pclient) {
        port_printf("malloc mqtt client failed\n");
        return NULL;
    }
    
    memset(pclient, 0, sizeof(mqtt_client_t));
    rc = mqtt_client_init(pclient, conn, tls_config);
    if (rc != SUCCESS_RETURN) {
        port_free(pclient);
        return NULL;
    }
    
    return pclient;
}


extern int MQTTPacket_len(int rem_len);
extern int MQTTSerialize_connectLength(MQTTPacket_connectData *options);

static int _get_connect_length(MQTTPacket_connectData *options)
{
    return MQTTPacket_len(MQTTSerialize_connectLength(options)); 
}


static int reset_send_buffer(mqtt_client_t *pclient)
{
    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    if (pclient->buf_send) {
        port_free(pclient->buf_send);
        pclient->buf_send = NULL;
    }

    return SUCCESS_RETURN;
}

static int reset_recv_buffer(mqtt_client_t *pclient)
{
    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    if (pclient->buf_read) {
        port_free(pclient->buf_read);
        pclient->buf_read = NULL;
        pclient->buf_size_read = 0;
    }

    return SUCCESS_RETURN;
}

static int alloc_send_buffer(mqtt_client_t *pclient, int len)
{
    int tmp_len;
    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    tmp_len = len + MQTT_DYNBUF_SEND_MARGIN;
    if (tmp_len > pclient->buf_size_send_max) {
        tmp_len = pclient->buf_size_send_max;
    }

    if(pclient->buf_send != NULL){
        mqtt_warning("send buffer is not NULL, free it first");
        port_free(pclient->buf_send);
    }

    pclient->buf_send = port_malloc(tmp_len);
    if (NULL == pclient->buf_send) {
        mqtt_err("malloc send buffer failed");
        return ERROR_MALLOC;
    }

    memset(pclient->buf_send, 0, tmp_len);
    pclient->buf_size_send = tmp_len;

    return SUCCESS_RETURN;
}


static int alloc_recv_buffer(mqtt_client_t *pclient, int len)
{
    int tmp_len;
    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    tmp_len = len + MQTT_DYNBUF_RECV_MARGIN;
    if (tmp_len > pclient->buf_size_read_max) {
        tmp_len = pclient->buf_size_read_max;
    }

    if(pclient->buf_read != NULL){  // need realloc
        char *tmp = port_malloc(tmp_len);
        if(tmp == NULL){
            mqtt_err("realloc recv buffer failed");
            return ERROR_MALLOC;
        }
        memset(tmp, 0, tmp_len);
        memcpy(tmp, pclient->buf_read, pclient->buf_size_read < tmp_len ? pclient->buf_size_read : tmp_len);
        port_free(pclient->buf_read);
        pclient->buf_read = tmp;
    }else{
        pclient->buf_read = port_malloc(tmp_len);
        if (NULL == pclient->buf_read) {
            mqtt_err("malloc recv buffer failed");
            return ERROR_MALLOC;
        }
        memset(pclient->buf_read, 0, tmp_len);
    }

    pclient->buf_size_read = tmp_len;

    return SUCCESS_RETURN;
}



static mqtt_topic_info_t *mqtt_topic_info_create(unsigned short packet_id, 
                                            mqtt_qos_t qos, 
                                            uint8_t dup, 
                                            uint8_t retain, 
                                            const char *topic_name, 
                                            int payload_len, 
                                            unsigned char *payload)
{
    mqtt_topic_info_t *topic_info = NULL;
    topic_info = (mqtt_topic_info_t *)port_malloc(sizeof(mqtt_topic_info_t));
    if (NULL == topic_info) {
        mqtt_err("malloc topic info failed");
        return NULL;
    }

    topic_info->packet_id = packet_id;
    topic_info->qos = qos;
    topic_info->dup = dup;
    topic_info->retain = retain;
    topic_info->topic_name = (char *)port_malloc(strlen(topic_name) + 1);
    if (NULL == topic_info->topic_name) {
        mqtt_err("malloc topic name failed");
        port_free(topic_info);
        return NULL;
    }
    strcpy(topic_info->topic_name, topic_name);
    topic_info->payload_len = payload_len;
    topic_info->payload = (unsigned char *)port_malloc(payload_len);
    if (NULL == topic_info->payload) {
        mqtt_err("malloc payload failed");
        port_free(topic_info->topic_name);
        port_free(topic_info);
        return NULL;
    }
    memcpy(topic_info->payload, payload, payload_len);
    return topic_info;
}



static void mqtt_topic_info_free(mqtt_topic_info_t *topic_info)
{
    if (topic_info) {
        if (topic_info->topic_name) {
            port_free(topic_info->topic_name);
        }
        if (topic_info->payload) {
            port_free(topic_info->payload);
        }
        port_free(topic_info);
    }
}




static int mc_send_packet(mqtt_client_t *pclient, char *buf, int length, utils_time_t *time)
{
    int rc = FAIL_RETURN;
    int sent = 0;
    unsigned int left_time = 0;
    int c = 0;

    if (NULL == pclient || NULL == buf || !time) {
        return rc;
    }

    while (sent < length && !utils_time_is_expired(time)) {
        left_time = utils_time_left(time);
        left_time = (left_time == 0) ? 1 : left_time;

        rc = pclient->ipstack.write(&pclient->ipstack, &buf[sent], length - sent, left_time);

        if(rc < 0){
            break;
        }

        sent += rc;
    }

    if (sent == length) {
        rc = SUCCESS_RETURN;
    } else {
        rc = MQTT_NETWORK_ERROR;
    }

    return rc;
}

static int MQTTConnect(mqtt_client_t *pclient)
{
    int len = 0;
    int rc = FAIL_RETURN;
    MQTTPacket_connectData *pConnectParams = NULL;
    utils_time_t connectTimer;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    pConnectParams = &(pclient->connect_data);

    len = _get_connect_length(pConnectParams);

    rc = alloc_send_buffer(pclient, len);
    if (rc != SUCCESS_RETURN) {
        mqtt_err("alloc send buffer failed");
        return rc;
    }

    len = MQTTSerialize_connect(pclient->buf_send, pclient->buf_size_send, pConnectParams);
    if (len <= 0) {
        mqtt_err("serialize connect packet failed");
        reset_send_buffer(pclient);
        return MQTT_CONNECT_PACKET_ERROR;
    }

    // send connect packet
    utils_time_init(&connectTimer);
    utils_time_countdown_ms(&connectTimer, pclient->request_timeout_ms);
    rc = mc_send_packet(pclient, pclient->buf_send, len, &connectTimer);
    if (rc != SUCCESS_RETURN) {
        mqtt_err("send connect packet failed");
        reset_send_buffer(pclient);
        return MQTT_NETWORK_ERROR;
    }

    // 发送完毕后，就可以清空send buffer
    reset_send_buffer(pclient);
    return SUCCESS_RETURN;
}

// 解码 mqtt 数据包
static int mc_decode_packet(mqtt_client_t *pclient, int *value, int timeout)
{
    char i;
    int multiplier = 1;
    int len = 0;
    const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;

    if (NULL == pclient || NULL == value) {
        return FAIL_RETURN;
    }

    *value = 0;
    do {
        int rc = MQTTPACKET_READ_ERROR;

        if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
            return MQTTPACKET_READ_ERROR; /* bad data */
        }

        rc = pclient->ipstack.read(&pclient->ipstack, &i, 1, timeout == 0 ? 1 : timeout);
        if (rc == 0) {
            return FAIL_RETURN;
        } else if (rc != 1) {
            return MQTT_NETWORK_ERROR;
        }

        *value += (i & 127) * multiplier;
        multiplier *= 128;
    } while ((i & 128) != 0);

    return len;
}


// 读取mqtt 数据包
static int mc_read_packet(mqtt_client_t *pclient, utils_time_t *timer, unsigned int *packet_type)
{
    MQTTHeader header = {0};
    int len = 0;
    int rem_len = 0;
    int rc = 0;
    unsigned int left_t = 0;

    if (NULL == pclient || NULL == timer || NULL == packet_type) {
        return FAIL_RETURN;
    }

    // 申请recv buffer
    rc = alloc_recv_buffer(pclient, 0);
    if (rc != SUCCESS_RETURN) {
        mqtt_err("alloc recv buffer failed");
        return rc;
    }

    // 1. 读取固定头部
    left_t = utils_time_left(timer);
    left_t = (left_t == 0) ? 1 : left_t;
    rc = pclient->ipstack.read(&pclient->ipstack, pclient->buf_read, 1, left_t);
    if (rc == 0) { // timeout
        *packet_type = MQTT_CPT_RESERVED;
        return SUCCESS_RETURN;
    }else if(rc != 1){
        mqtt_err("mqtt read error, rc:%d", rc);
        return MQTT_NETWORK_ERROR;
    }

    len = 1;

    // 2. 读取剩余长度
    left_t = utils_time_left(timer);
    left_t = (left_t == 0) ? 1 : left_t;
    rc = mc_decode_packet(pclient, &rem_len, left_t);
    if (rc < 0) {
        mqtt_err("decode packet error, rc:%d", rc);
        return rc;
    }

    len += MQTTPacket_encode(pclient->buf_read + 1, rem_len); // encode remaining length
    rc = alloc_recv_buffer(pclient, rem_len + len);
    if (rc != SUCCESS_RETURN) {
        mqtt_err("alloc recv buffer failed");
        return rc;
    }

    // 检查收到的数据长度是否超过mqtt read buffer 的长度
    if ((rem_len > 0) && ((rem_len + len) > pclient->buf_size_read)) {
        int needReadLen;
        int remainDataLen;
        char *remainDataBuf;

        mqtt_err("mqtt read buffer is too short, mqttReadBufLen : %u, remainDataLen : %d", pclient->buf_size_read, rem_len);
        needReadLen = pclient->buf_size_read - len;
        left_t = utils_time_left(timer);
        left_t = (left_t == 0) ? 1 : left_t;
        rc = pclient->ipstack.read(&pclient->ipstack, pclient->buf_read + len, needReadLen, left_t);
        if (rc < 0) {
            mqtt_err("mqtt read error");
            
            return MQTT_NETWORK_ERROR;
        } else if (rc != needReadLen) {
            mqtt_warning("mqtt read timeout");
            
            return FAIL_RETURN;
        }

        /* drop data whitch over the length of mqtt buffer */
        remainDataLen = rem_len - needReadLen;
        remainDataBuf = port_malloc(remainDataLen + 1);
        if (!remainDataBuf) {
            mqtt_err("allocate remain buffer failed");
            
            return FAIL_RETURN;
        }


        left_t = utils_time_left(timer);
        left_t = (left_t == 0) ? 1 : left_t;
        rc = pclient->ipstack.read(&pclient->ipstack, remainDataBuf, remainDataLen, left_t);
        if (rc < 0) {
            mqtt_err("mqtt read error");
            port_free(remainDataBuf);
            remainDataBuf = NULL;
            
            return MQTT_NETWORK_ERROR;
        } else if (rc != remainDataLen) {
            mqtt_warning("mqtt read timeout");
            port_free(remainDataBuf);
            remainDataBuf = NULL;
            
            return FAIL_RETURN;
        }

        port_free(remainDataBuf);
        remainDataBuf = NULL;

        
        *packet_type = MQTT_CPT_RESERVED;

        return SUCCESS_RETURN;

    }

    /* 3. read the rest of the buffer using a callback to supply the rest of the data */
    left_t = utils_time_left(timer);
    left_t = (left_t == 0) ? 1 : left_t;

    rc = pclient->ipstack.read(&pclient->ipstack, pclient->buf_read + len, rem_len, left_t);
    if (rem_len > 0) {
        if (rc < 0) {
            mqtt_err("mqtt read error");
            
            return MQTT_NETWORK_ERROR;
        } else if (rc != rem_len) {
            mqtt_warning("mqtt read timeout");
            
            return FAIL_RETURN;
        }
    }

    header.byte = pclient->buf_read[0];
    *packet_type = MQTT_HEADER_GET_TYPE(header.byte);
    if ((len + rem_len) < pclient->buf_size_read) {
        pclient->buf_read[len + rem_len] = '\0';
    }
    
    return SUCCESS_RETURN;
}


static int mc_handle_recv_CONNACK(mqtt_client_t *pclient)
{
    int rc = SUCCESS_RETURN;
    unsigned char connack_rc = 255;
    unsigned char sessionPresent = 0;
    
    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    if(MQTTDeserialize_connack((unsigned char *)&sessionPresent, &connack_rc, 
                            (unsigned char *)pclient->buf_read, pclient->buf_size_read) != 1){
        mqtt_err("deserialize CONNACK packet failed");
        return MQTT_CONNECT_ACK_PACKET_ERROR;
    }

    switch (connack_rc) {
        case MC_CONNECTION_ACCEPTED:
            rc = SUCCESS_RETURN;
            break;
        case MC_CONNECTION_REFUSED_UNACCEPTABLE_PROTOCOL_VERSION:
            rc = MQTT_CONANCK_UNACCEPTABLE_PROTOCOL_VERSION_ERROR;
            break;
        case MC_CONNECTION_REFUSED_IDENTIFIER_REJECTED:
            rc = MQTT_CONNACK_IDENTIFIER_REJECTED_ERROR;
            break;
        case MC_CONNECTION_REFUSED_SERVER_UNAVAILABLE:
            rc = MQTT_CONNACK_SERVER_UNAVAILABLE_ERROR;
            break;
        case MC_CONNECTION_REFUSED_BAD_USERDATA:
            rc = MQTT_CONNACK_BAD_USERDATA_ERROR;
            break;
        case MC_CONNECTION_REFUSED_NOT_AUTHORIZED:
            rc = MQTT_CONNACK_NOT_AUTHORIZED_ERROR;
            break;
        default:
            rc = MQTT_CONNACK_UNKNOWN_ERROR;
            break;
    }

    return rc;
}


static int mc_wait_CONNACK(mqtt_client_t *pclient)
{
#define WAIT_CONNACK_MAX (10)
    unsigned char wait_connack = 0;
    unsigned int packetType = 0;
    int rc = 0;
    utils_time_t timer;

    if (!pclient) {
        return FAIL_RETURN;
    }

    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->request_timeout_ms);

    do {
        /* read the socket, see what work is due */

        rc = mc_read_packet(pclient, &timer, &packetType);
        if (rc != SUCCESS_RETURN) {
            mqtt_err("readPacket error,result = %d", rc);
            //port_mutex_lock(pclient->lock_read_buf);
            reset_recv_buffer(pclient);
            
            return rc;
        }

        if (++wait_connack > WAIT_CONNACK_MAX) {
            mqtt_err("wait connack timeout");
            //port_mutex_lock(c->lock_read_buf);
            reset_recv_buffer(pclient);
            
            return MQTT_NETWORK_ERROR;
        }
    } while (packetType != CONNACK);
    //port_mutex_lock(c->lock_read_buf);

    rc = mc_handle_recv_CONNACK(pclient);
    reset_recv_buffer(pclient);
    

    if (SUCCESS_RETURN != rc) {
        mqtt_err("recvConnackProc error,result = %d", rc);
    }

    return rc;
}


static int mqtt_connect(mqtt_client_t *pClient)
{
#define RETRY_TIME_LIMIT    (8+1)
#define RETRY_INTV_PERIOD   (2000)
    int rc = FAIL_RETURN;
    int try_count = 1;
    int userKeepAliveInterval = 0;

    if (NULL == pClient) {
        return NULL_VALUE_ERROR;
    }
    userKeepAliveInterval = pClient->connect_data.keepAliveInterval;
    // modify by jsq, do not *2
    //pClient->connect_data.keepAliveInterval = (userKeepAliveInterval * 2);
    pClient->connect_data.keepAliveInterval = (userKeepAliveInterval * 1);
    
    if(pClient->connect_data.keepAliveInterval > CONFIG_MQTT_KEEPALIVE_INTERVAL_MAX) {
        pClient->connect_data.keepAliveInterval = CONFIG_MQTT_KEEPALIVE_INTERVAL_MAX;
    }
    mqtt_info("connect params: MQTTVersion=%d, clientID=%s, keepAliveInterval=%d, username=%s",
              pClient->connect_data.MQTTVersion,
              pClient->connect_data.clientID.cstring,
              pClient->connect_data.keepAliveInterval,
              pClient->connect_data.username.cstring);

    /* 此时已经建立TCP/TLS连接，准备mqtt 协议层的连接 */
    do {
        rc = MQTTConnect(pClient);
        pClient->connect_data.keepAliveInterval = userKeepAliveInterval;

        if (rc != SUCCESS_RETURN) {
            pClient->ipstack.disconnect(&pClient->ipstack);
            mqtt_err("send connect packet failed, rc = %d", rc);
            return rc;
        }
        // 等待CONNACK
        rc = mc_wait_CONNACK(pClient);

        if (rc <= MQTT_CONNACK_NOT_AUTHORIZED_ERROR && rc >= MQTT_CONANCK_UNACCEPTABLE_PROTOCOL_VERSION_ERROR) {
            mqtt_err("received reject ACK from MQTT server! rc = %d", rc);
            pClient->ipstack.disconnect(&pClient->ipstack);
            return MQTT_CONNECT_ERROR;
        }

        if (SUCCESS_RETURN != rc) {
            mqtt_err("wait connect ACK timeout! rc = %d", rc);
            mqtt_warning("tried [%d/%d] times CONN, waiting for %d ms...", try_count, RETRY_TIME_LIMIT - 1, RETRY_INTV_PERIOD);

            port_sleep_ms(RETRY_INTV_PERIOD);

            pClient->ipstack.disconnect(&pClient->ipstack);
            pClient->ipstack.connect(&pClient->ipstack);
            continue;
        } else {
            break;
        }

    } while (++try_count < RETRY_TIME_LIMIT);

    if (try_count == RETRY_TIME_LIMIT) {
        return MQTT_CONNECT_ERROR;
    }
    pClient->keepalive_probes = 0;
    mc_set_client_state(pClient, MC_STATE_CONNECTED);

    utils_time_countdown_ms(&pClient->next_ping_time, pClient->connect_data.keepAliveInterval * 1000);

    mqtt_info("mqtt connect success!");
    return SUCCESS_RETURN;
}


int mqtt_client_connect(mqtt_client_t *pclient)
{
    int rc = FAIL_RETURN;
    int retry_max = 3;
    int retry_cnt = 1;
    int retry_interval_ms = 1000;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    // 建立tcp或tls 连接
    do{
        mqtt_debug("start TCP or TLS connect, retry_cnt=%d,, retry max:%d", retry_cnt, retry_max);

        rc = pclient->ipstack.connect(&pclient->ipstack);
        if(rc != SUCCESS_RETURN){
            pclient->ipstack.disconnect(&pclient->ipstack);
            mqtt_err("ipstack connect failed, rc=%d", rc);
            
            if(rc == ERROR_CERTIFICATE_EXPIRED){
                mqtt_err("certificate is expired! rc = %d", rc);
                rc = ERROR_CERT_VERIFY_FAIL;
            }else{
                rc = MQTT_NETWORK_CONNECT_ERROR;
            }

            port_sleep_ms(retry_interval_ms);
            continue;
        }else{
            mqtt_info("ipstack connect success, retry cnt:%d, retry max:%d", retry_cnt, retry_max);
            break;
        }
    } while(++retry_cnt <= retry_max);

    // 启动MQTT 连接
    rc = mqtt_connect(pclient);

    return rc;
}


static int mc_send_ping_packet(mqtt_client_t *pclient)
{
    int rc = FAIL_RETURN;
    int len = 0;
    utils_time_t timer;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }


    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, 1000);

    rc = alloc_send_buffer(pclient, 0);
    if (rc < 0) {
        mqtt_err("alloc send buffer failed");
        return FAIL_RETURN;
    }

    len = MQTTSerialize_pingreq(pclient->buf_send, pclient->buf_size_send);
    if (len <= 0) {
        mqtt_err("serialize ping packet failed");
        reset_send_buffer(pclient);
        return MQTT_PING_PACKET_ERROR;
    }

    rc = mc_send_packet(pclient, pclient->buf_send, len, &timer);
    if (rc != SUCCESS_RETURN) {
        mqtt_err("send ping packet failed");
        reset_send_buffer(pclient);
        return MQTT_NETWORK_ERROR;
    }

    reset_send_buffer(pclient);
    return SUCCESS_RETURN;
}





static int mc_keepalive_ping(mqtt_client_t *pclient)
{
    int rc = FAIL_RETURN;
    int len = 0;
    utils_time_t timer;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    if(MC_STATE_CONNECTED != mc_get_client_state(pclient)){
        return SUCCESS_RETURN;
    }

    // 检查是否需要发送心跳包, 如果不需要发送心跳包，直接返回
    if(!utils_time_is_expired(&pclient->next_ping_time)){
        return SUCCESS_RETURN;
    }

    // 运行至此，需要发送ping，先更新下次发送心跳包的时间
    utils_time_countdown_ms(&pclient->next_ping_time, pclient->connect_data.keepAliveInterval * 1000);

    // 发送ping包
    mqtt_info("send MQTT ping...");

    rc = mc_send_ping_packet(pclient);
    if(rc != SUCCESS_RETURN){
        if(rc == MQTT_NETWORK_ERROR){
            mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
        }
        mqtt_err("send ping packet failed");
        return rc;
    }

    

    // 更新keepalive probes
    pclient->keepalive_probes++;

    // 通过keepalive probes 判断是否需要重连
    if(pclient->keepalive_probes >= CONFIG_MQTT_KEEPALIVE_PROBES_MAX){
        mqtt_err("keepalive probes reach max, need to reconnect...");
        pclient->keepalive_probes = 0;
        mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
    }

    return SUCCESS_RETURN;
}


static int mc_attempt_reconnect(mqtt_client_t *pclient)
{
    int rc;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }
    
    // 先主动断开连接，此时可能上次重连还正在进行
    pclient->ipstack.disconnect(&pclient->ipstack);

    // 重连
    rc = mqtt_client_connect(pclient);
    if (rc != SUCCESS_RETURN && rc != MQTT_CONNECT_BLOCK) {
        mqtt_err("mqtt reconnect failed, rc=%d", rc);
    }

    return rc;
}

static int mc_handle_reconnect(mqtt_client_t *pclient)
{
    int rc = FAIL_RETURN;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    mqtt_info("mqtt waiting reconnect...");
    // 判断下次重连间隔是否到达
    if (!utils_time_is_expired(&pclient->reconnect_param.reconnect_next_time)) {
        // 未到重连时间，延时退出
        port_sleep_ms(100);
        return FAIL_RETURN;
    }

    mqtt_info("mqtt start reconnect...");
    // 准备重连
    rc = mc_attempt_reconnect(pclient);
    if(rc == SUCCESS_RETURN){
        // 更新连接状态
        mc_set_client_state(pclient, MC_STATE_CONNECTED);
        return SUCCESS_RETURN;
    }else if (rc == MQTT_CONNECT_BLOCK) {
        return rc;
    } else {
        // 更新下次重连间隔时间, 重连间隔为2,4,8,16,32,..max
        if(pclient->reconnect_param.reconnect_time_interval_ms < CONFIG_MQTT_RECONNECT_INTERVAL_MAX_MS){
            pclient->reconnect_param.reconnect_time_interval_ms *= 2;
        }else{
            pclient->reconnect_param.reconnect_time_interval_ms = CONFIG_MQTT_RECONNECT_INTERVAL_MAX_MS;
        }

        // 重连间隔时间乘2后最大值为 CONFIG_MQTT_RECONNECT_INTERVAL_MAX_MS，避免出现59*2 的大值，需要再次判断
        if(pclient->reconnect_param.reconnect_time_interval_ms > CONFIG_MQTT_RECONNECT_INTERVAL_MAX_MS){
            pclient->reconnect_param.reconnect_time_interval_ms = CONFIG_MQTT_RECONNECT_INTERVAL_MAX_MS;
        }
    }

    // 根据重连间隔，更新下次重连时间戳（timer)
    utils_time_countdown_ms(&pclient->reconnect_param.reconnect_next_time, 
                        pclient->reconnect_param.reconnect_time_interval_ms);
    
    return rc;
}


static void mc_keepalive(mqtt_client_t *pclient)
{
    int rc = 0;
    mc_state_t currentState = MC_STATE_INVALID;
    
    if(NULL == pclient){
        return;
    }

    // 周期发送心跳包
    mc_keepalive_ping(pclient);

    // 检查连接状态，判断是否需要重连  
    currentState = mc_get_client_state(pclient);
    do{
        // 如果超过重连等待时间，尝试重连
        if(currentState == MC_STATE_DISCONNECTED_RECONNECTING || 
           currentState == MC_STATE_CONNECT_BLOCK){
            // 计算是否需要重连
            rc = mc_handle_reconnect(pclient);
            if(rc != SUCCESS_RETURN){
                mqtt_err("mqtt handle reconnect failed, rc=%d", rc);
            }else if(rc == MQTT_CONNECT_BLOCK){
                // 阻塞重连
                mqtt_debug("mqtt connect block, waiting for next reconnect...");
            }else{
                mqtt_info("network is reconnected.");
                // 重连成功后，重连间隔时间重置为min，下次再次断开重连后，直接使用min
                pclient->reconnect_param.reconnect_time_interval_ms = CONFIG_MQTT_RECONNECT_INTERVAL_MIN_MS;

            }

            break;
        }

        // 如果连接断开断开，停止 ping，立刻重连
        if(currentState == MC_STATE_DISCONNECTED){
            mqtt_err("mqtt disconnected, start reconnect...");
            // 设置重连间隔为min
            pclient->reconnect_param.reconnect_time_interval_ms = CONFIG_MQTT_RECONNECT_INTERVAL_MIN_MS;
            // 更新下次重连时间
            utils_time_countdown_ms(&pclient->reconnect_param.reconnect_next_time, 
                                    pclient->reconnect_param.reconnect_time_interval_ms);

            // 更新状态为 MC_STATE_DISCONNECTED_RECONNECTING，表示正在准备重连，防止重连过程中再次重连，下次poll，会自动重连
            mc_set_client_state(pclient, MC_STATE_DISCONNECTED_RECONNECTING);

            break;
        }
    } while(0);
}


static int mc_add_pubinfo_to_hashmap(mqtt_client_t *pclient, mqtt_topic_info_t *topic_info)
{
    mqtt_qos1_msg_hashmap_node_t *node = NULL;
    MQTTString  topic = MQTTString_initializer;
    int tmp_len;
    
    if(pclient == NULL || topic_info == NULL){
        return NULL_VALUE_ERROR;
    }

    tmp_len = strlen(topic_info->topic_name) + topic_info->payload_len + MQTT_DYNBUF_SEND_MARGIN;
    if(tmp_len > CONFIG_MQTT_BUFFER_SEND_MAX){
        mqtt_err("topic info is too long, payload_len=%d, topic_name=%s", topic_info->payload_len, topic_info->topic_name);
        goto err_end;
    }

    node = (mqtt_qos1_msg_hashmap_node_t *)mqtt_malloc(sizeof(mqtt_qos1_msg_hashmap_node_t));
    if(node == NULL){
        return FAIL_RETURN;
    }
    memset(node, 0, sizeof(mqtt_qos1_msg_hashmap_node_t));
    
    node->packet_id = (int)topic_info->packet_id;

    node->buf = (unsigned char *)mqtt_malloc(tmp_len);

    topic.cstring = topic_info->topic_name;
    node->len = MQTTSerialize_publish(node->buf, 
                            tmp_len, 
                            1,                                      // dup 为1
                            topic_info->qos, 
                            topic_info->retain, 
                            topic_info->packet_id,                  // dup packet id
                            topic, 
                            topic_info->payload, 
                            topic_info->payload_len); 
    
    utils_time_start(&node->pub_start_time);

    mqtt_debug("hashmap add key:%d\n", node->packet_id);
    HASH_ADD_INT(pclient->qos1_msg_hashmap_table, packet_id, node);

    return SUCCESS_RETURN;

err_end:
    if(node){
        if(node->buf){
            mqtt_free(node->buf);
            node->buf = NULL;
        }
        mqtt_free(node);
    }
    return -1;
}

static int mc_del_pubinfo_from_hashmap(mqtt_client_t *pclient, unsigned short packet_id)
{
    mqtt_qos1_msg_hashmap_node_t *node = NULL;
    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    mqtt_debug("mc_del_pubinfo_from_hashmap, IN packet_id=%d", packet_id);
    int id = (int)packet_id;

    HASH_FIND_INT(pclient->qos1_msg_hashmap_table, &id, node);
    if(node != NULL){
        mqtt_debug("mc_del_pubinfo_from_hashmap, find packet_id=%d", packet_id);
        mqtt_free(node->buf);
        HASH_DEL(pclient->qos1_msg_hashmap_table, node);
        mqtt_free(node);
    }
}




static int mc_handle_recv_PUBACK(mqtt_client_t *pclient)
{
    unsigned short packet_id;
    unsigned char dup = 0;
    unsigned char type = 0;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    if(MQTTDeserialize_ack(&type, &dup, &packet_id, pclient->buf_read, pclient->buf_size_read) != 1){
        return MQTT_PUBLISH_ACK_PACKET_ERROR;
    }

    // 根据packet_id，从qos1_msg_hashmap_table中删除
    mc_del_pubinfo_from_hashmap(pclient, packet_id);

    return SUCCESS_RETURN;
}


static mqtt_subscribe_hashmap_node_t *mc_get_subscribe_hashmap_node_by_packet_id(mqtt_client_t *pclient, unsigned short packet_id)
{
    mqtt_subscribe_hashmap_node_t *node, *node_next;

    if(pclient == NULL){
        return NULL;
    }

    // subscribe hashmap的主键key为topic name，所以如果通过packet_id 查找节点，需要遍历hash
    HASH_ITER(hh, pclient->subscribe_hashmap_table, node, node_next) {
        if(node->packet_id == packet_id){
            return node;
        }
    }

    return NULL;
}



static int mc_handle_recv_SUBACK(mqtt_client_t *pclient)
{   
    unsigned short packet_id;
    int i = 0, count = 0, rc = 0, j = 0;
    int grantedQos[CONFIG_MQTT_MUTLI_SUBSCRIBE_MAX];
    mqtt_subscribe_hashmap_node_t *node;


    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }


    rc = MQTTDeserialize_suback(&packet_id, CONFIG_MQTT_MUTLI_SUBSCRIBE_MAX, &count, grantedQos, pclient->buf_read, pclient->buf_size_read);
    if(rc < 0){
        mqtt_err("mc_handle_recv_SUBACK failed, rc=%d", rc);
        return MQTT_SUBSCRIBE_ACK_PACKET_ERROR;
    }

    node = mc_get_subscribe_hashmap_node_by_packet_id(pclient, packet_id);

    if(node != NULL){
        mqtt_info("mc_handle_recv_SUBACK, packet_id=%d, topic=%s", packet_id, node->topic_name);
        node->sub_succ = 1;
    }

    return SUCCESS_RETURN;
}


static int mc_handle_recv_PUBLISH(mqtt_client_t *pclient)
{
    int rc = SUCCESS_RETURN;
    MQTTString topicName;
    int qos = 0;
    uint32_t payload_len = 0;
    mqtt_topic_info_t recv_topic_msg;
    mqtt_topic_info_t *topic_info;
    mqtt_client_rte_job_info_t *job_info;

    if (NULL == pclient) {
        return NULL_VALUE_ERROR;
    }

    memset(&recv_topic_msg, 0, sizeof(mqtt_topic_info_t));
    memset(&topicName, 0, sizeof(MQTTString));

    mqtt_debug("mc_handle_recv_PUBLISH");

    if(1 != MQTTDeserialize_publish((unsigned char *)&recv_topic_msg.dup,
                                (int *)&qos,
                                (unsigned char *)&recv_topic_msg.retain,
                                (unsigned short *)&recv_topic_msg.packet_id,
                                &topicName,
                                (unsigned char **)&recv_topic_msg.payload,
                                (int *)&payload_len,
                                (unsigned char *)pclient->buf_read,
                                pclient->buf_size_read))
    {
        return MQTT_PUBLISH_PACKET_ERROR;
    }

    recv_topic_msg.qos = qos;
    recv_topic_msg.payload_len = payload_len;

    if(topicName.lenstring.len == 0 || topicName.lenstring.data == NULL){
        mqtt_err("topicName is empty");
        return MQTT_PUBLISH_PACKET_ERROR;
    }

    job_info = (mqtt_client_rte_job_info_t *)mqtt_malloc(sizeof(mqtt_client_rte_job_info_t));
    if(job_info == NULL){
        mqtt_err("mqtt_malloc failed");
        return FAIL_RETURN;
    }

    topic_info = (mqtt_topic_info_t *)mqtt_malloc(sizeof(mqtt_topic_info_t));
    if(topic_info == NULL){
        mqtt_err("mqtt_malloc failed");
        mqtt_free(job_info);
        return FAIL_RETURN;
    }

    memset(job_info, 0, sizeof(mqtt_client_rte_job_info_t));
    memset(topic_info, 0, sizeof(mqtt_topic_info_t));

    job_info->job_type = MC_JOB_TYPE_SUB_MSG_NOTIFY;
    job_info->topic_info = topic_info;

    // 赋值topic_info
    /*
    typedef struct{
        unsigned short packet_id;
        mqtt_qos_t  qos;
        unsigned char dup;
        unsigned char retain;
        char *topic_name;
        unsigned int payload_len;
        unsigned char *payload;
    } mqtt_topic_info_t;
     */
    topic_info->packet_id = recv_topic_msg.packet_id;
    topic_info->qos = recv_topic_msg.qos;
    topic_info->dup = recv_topic_msg.dup;
    topic_info->retain = recv_topic_msg.retain;

    topic_info->topic_name = (char *)mqtt_malloc(topicName.lenstring.len + 1);
    if(topic_info->topic_name == NULL){
        mqtt_err("mqtt_malloc failed");
        mqtt_free(topic_info);
        mqtt_free(job_info);
        return FAIL_RETURN;
    }
    memset(topic_info->topic_name, 0, topicName.lenstring.len + 1);
    memcpy(topic_info->topic_name, topicName.lenstring.data, topicName.lenstring.len);

    topic_info->payload_len = recv_topic_msg.payload_len;

    topic_info->payload = (unsigned char *)mqtt_malloc(topic_info->payload_len + 1);
    if(topic_info->payload == NULL){
        mqtt_err("mqtt_malloc failed");
        mqtt_free(topic_info->topic_name);
        mqtt_free(topic_info);
        mqtt_free(job_info);
        return FAIL_RETURN;
    }
    memset(topic_info->payload, 0, topic_info->payload_len + 1);
    memcpy(topic_info->payload, recv_topic_msg.payload, topic_info->payload_len);

    // add to rte_job_queue
    cQPost(pclient->rte_job_queue, (void *)job_info);


    return SUCCESS_RETURN;

}


static int mc_cycle_attempt_recv(mqtt_client_t *pclient, utils_time_t *timer)
{
    int rc = SUCCESS_RETURN;
    unsigned int packetType = 0;
    mc_state_t currentState = MC_STATE_INVALID;

    if (NULL == pclient || NULL == timer) {
        return FAIL_RETURN;
    }

    currentState = mc_get_client_state(pclient);
    if (currentState != MC_STATE_CONNECTED) {
        return MQTT_STATE_ERROR;
    }

    
    // 读socket, 
    rc = mc_read_packet(pclient, timer, &packetType);

    if (rc != SUCCESS_RETURN) {
        reset_recv_buffer(pclient);
        
        if(rc == MQTT_NETWORK_ERROR){
            mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
        }
        mqtt_err("mc_read_packet failed, rc=%d", rc);
        return MQTT_NETWORK_ERROR;
    }

    if(packetType == MQTT_CPT_RESERVED){
        reset_recv_buffer(pclient);
        return SUCCESS_RETURN;
    }

    // ！！！清空复位 keepalive probes
    pclient->keepalive_probes = 0;

    // 根据帧类型处理
    switch (packetType) {
    case CONNACK:
        mqtt_debug("connack received");
        break;
#if !CONFIG_MQTT_ONLY_SUPPORT_QOS0
    case PUBACK:
        mqtt_debug("puback received");
        rc = mc_handle_recv_PUBACK(pclient);
        if(rc != SUCCESS_RETURN){
            mqtt_err("mc_handle_recv_PUBACK failed, rc=%d", rc);
        }
        break;
#endif
    case SUBACK:
        mqtt_debug("suback received");
        rc = mc_handle_recv_SUBACK(pclient);
        if(rc != SUCCESS_RETURN){
            mqtt_err("mc_handle_recv_SUBACK error, rc=%d", rc);
        }
        break;
    
    case PUBLISH:
        rc = mc_handle_recv_PUBLISH(pclient);
        if(rc != SUCCESS_RETURN){
            mqtt_err("mc_handle_recv_PUBLISH error, rc=%d", rc);
        }
        break;
    
    case UNSUBACK:
        break;

    case PINGRESP:
        mqtt_debug("pingresp received");
        break;

    default:
        mqtt_err("unknown packetType=%d", packetType);
        break;
    }

    reset_recv_buffer(pclient);

    return rc;
   
}


static int MQTTRePublish(mqtt_client_t *pclient, char *buf_send, int len)
{
    utils_time_t timer;
    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->request_timeout_ms);

    if(mc_send_packet(pclient, buf_send, len, &timer) != SUCCESS_RETURN){
        return MQTT_NETWORK_ERROR;
    }

    return SUCCESS_RETURN;
}


static int mc_qos1_msg_proc(mqtt_client_t *pclient)
{
    int rc = 0;
    mc_state_t currentState = MC_STATE_INVALID;
    mqtt_qos1_msg_hashmap_node_t *node, *next_node;

    if(pclient == NULL || pclient->qos1_msg_hashmap_table == NULL){
        return NULL_VALUE_ERROR;
    }

    currentState = mc_get_client_state(pclient);
    if(currentState != MC_STATE_CONNECTED){
        return MQTT_STATE_ERROR;
    }

    // 遍历hashmap，处理qos1消息
    HASH_ITER(hh, pclient->qos1_msg_hashmap_table, node, next_node){
        // 检查发送是否超时
        if(utils_time_spend(&node->pub_start_time) <= (pclient->request_timeout_ms * 2)){
            continue;
        }

        // republish
        mqtt_debug("republish, packet id:%d", node->packet_id);
        rc = MQTTRePublish(pclient, node->buf, node->len);
        utils_time_start(&node->pub_start_time);

        if(rc == MQTT_NETWORK_ERROR){
            mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
            break;
        }

        // 更新该节点republish 次数
        node->repub_cnt++;
        mqtt_debug("packet id: %d, republish cnt:%d", node->packet_id, node->repub_cnt);
    }

    return SUCCESS_RETURN;
}



void mc_cycle_recv(mqtt_client_t *pclient)
{
    int rc = SUCCESS_RETURN;
    utils_time_t timer;

    if (NULL == pclient) {
        return;
    }

    if(mc_get_client_state(pclient) != MC_STATE_CONNECTED){
        // 重要，如果连接断开，不需要poll，但是需要sleep，否则会死循环
        port_sleep_ms(pclient->cycle_timeout_ms);
        return;
    }

    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->cycle_timeout_ms);

    do{
        unsigned int left_t;
        if(rc != SUCCESS_RETURN){
            mqtt_err("cycle err, rc=%d", rc);
        }

        // 读取数据包
        rc = mc_cycle_attempt_recv(pclient, &timer);

        if(rc == SUCCESS_RETURN){
            mc_qos1_msg_proc(pclient);
        }
        
        left_t = utils_time_left(&timer);
        if(left_t < 10){
            port_sleep_ms(left_t);
        }else{
            port_sleep_ms(10);
        }
    } while (!utils_time_is_expired(&timer));
  
}


static int MQTTPublish(mqtt_client_t *pclient, mqtt_topic_info_t *topic_msg)
{
    utils_time_t timer;
    uint16_t msg_id = 0;
    int rc = FAIL_RETURN;
    int len = 0;
    MQTTString  topic = MQTTString_initializer;
    mc_state_t currentState = MC_STATE_INVALID;


    if(pclient == NULL || topic_msg == NULL || topic_msg->payload == NULL){
        mqtt_err("mqtt publish failed, pclient=%p, topic_msg=%p", pclient, topic_msg);
        return NULL_VALUE_ERROR;
    }

    currentState = mc_get_client_state(pclient);

    if(currentState != MC_STATE_CONNECTED){
        mqtt_err("mqtt publish failed, state=%d", currentState);
        return MQTT_STATE_ERROR;
    }

    topic.cstring = topic_msg->topic_name;
    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->request_timeout_ms);

    if(alloc_send_buffer(pclient, strlen(topic_msg->topic_name) + topic_msg->payload_len) != SUCCESS_RETURN){
        mqtt_err("alloc send buffer failed");
        return FAIL_RETURN;
    }

    len = MQTTSerialize_publish((unsigned char *)pclient->buf_send, 
                                pclient->buf_size_send, 
                                0,
                                topic_msg->qos, 
                                topic_msg->retain, 
                                topic_msg->packet_id, 
                                topic, 
                                topic_msg->payload, 
                                topic_msg->payload_len);
    if(len <= 0){
        mqtt_err("MQTTSerialize_publish failed, len=%d", len);
        reset_send_buffer(pclient);
        return MQTT_PUBLISH_PACKET_ERROR;
    }

    // 发送数据包
    if(mc_send_packet(pclient, pclient->buf_send, len, &timer) != SUCCESS_RETURN){
        reset_send_buffer(pclient);
        return MQTT_NETWORK_ERROR;
    }

    reset_send_buffer(pclient);

    // 对于qos1的消息，将发送的消息存储到hashmap中，用于qos1 重试

#if !CONFIG_MQTT_ONLY_SUPPORT_QOS0
    //  qos1 todo
    if(topic_msg->qos == MQTT_QOS1){
        if(SUCCESS_RETURN != mc_add_pubinfo_to_hashmap(pclient, topic_msg)){
            mqtt_err("mc_add_pubinfo_to_hashmap failed");
            return FAIL_RETURN;
        }
    }
#endif
    
    return SUCCESS_RETURN;
}


static int MQTTSubscribe(mqtt_client_t *pclient, char *topic_name, mqtt_qos_t qos, unsigned short packet_id)
{
    int len = 0;
    utils_time_t timer;
    MQTTString topic = MQTTString_initializer;

    topic.cstring = topic_name;
    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->request_timeout_ms);

    if(alloc_send_buffer(pclient, strlen(topic_name)) != SUCCESS_RETURN){
        mqtt_err("alloc send buffer failed");
        return FAIL_RETURN;
    }

    len = MQTTSerialize_subscribe((unsigned char *)pclient->buf_send, 
                                pclient->buf_size_send, 
                                0, 
                                packet_id, 
                                1, 
                                &topic, 
                                (int *)&qos);
    if(len <= 0){
        mqtt_err("MQTTSerialize_subscribe failed, len=%d", len);
        reset_send_buffer(pclient);
        return MQTT_SUBSCRIBE_PACKET_ERROR;
    }

    mqtt_debug("%20s : %08d", "Packet Ident", packet_id);
    mqtt_debug("%20s : %s", "Topic", topic_name);
    mqtt_debug("%20s : %d", "QoS", (int)qos);
    mqtt_debug("%20s : %d", "Packet Length", len);

    if(mc_send_packet(pclient, pclient->buf_send, len, &timer) != SUCCESS_RETURN){
        mqtt_err("mc_send_packet failed");
        reset_send_buffer(pclient);
        return MQTT_NETWORK_ERROR;
    }

    reset_send_buffer(pclient);

    return SUCCESS_RETURN;
}


static int mc_resubscribe_proc(mqtt_client_t *pclient)
{
    int rc = 0;
    unsigned short packet_id = 0;
    mc_state_t currentState = MC_STATE_INVALID;
    mqtt_subscribe_hashmap_node_t *node, *next_node;


    if(pclient == NULL){
        mqtt_err("mqtt resubscribe failed, pclient=%p", pclient);
        return NULL_VALUE_ERROR;
    }

    currentState = mc_get_client_state(pclient);
    if(currentState != MC_STATE_CONNECTED){
        return MQTT_STATE_ERROR;
    }

    // 遍历订阅列表，重新订阅
    HASH_ITER(hh, pclient->subscribe_hashmap_table, node, next_node){
        if(node->sub_succ){
            continue;
        }

        // 检查发送是否超时
        if(utils_time_spend(&node->sub_start_time) <= (pclient->request_timeout_ms * 2)){
            continue;
        }

        utils_time_start(&node->sub_start_time);

        packet_id = mc_get_next_packet_id(pclient);
        node->packet_id = packet_id;

        // republish
        mqtt_debug("attempt to resubscribe, topic name:%s, qos:%d", node->topic_name, node->qos);
        rc = MQTTSubscribe(pclient, node->topic_name, node->qos, packet_id);
        if(rc != SUCCESS_RETURN){
            mqtt_err("MQTTSubscribe failed, rc=%d", rc);
            mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
            return rc;
        }
    }

    return SUCCESS_RETURN;
}


static int MQTTUnsubscribe(mqtt_client_t *pclient, char *topic_name)
{
    utils_time_t timer;
    MQTTString topic = MQTTString_initializer;
    int len = 0;
    unsigned short packet_id = 0;

    if(pclient == NULL || topic_name == NULL){
        return NULL_VALUE_ERROR;
    }

    if(mc_get_client_state(pclient) != MC_STATE_CONNECTED){
        mqtt_err("mqtt unsubscribe failed, curr client state is not connected");
        return MQTT_STATE_ERROR;
    }

    topic.cstring = topic_name;
    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->request_timeout_ms);

    packet_id = mc_get_next_packet_id(pclient);

    if(alloc_send_buffer(pclient, strlen(topic_name)) != SUCCESS_RETURN){
        mqtt_err("alloc send buffer failed");
        return FAIL_RETURN;
    }

    len = MQTTSerialize_unsubscribe((unsigned char *)pclient->buf_send, 
                                pclient->buf_size_send, 
                                0, 
                                packet_id,
                                1,  
                                &topic);
    if(len <= 0){
        mqtt_err("MQTTSerialize_unsubscribe failed, len=%d", len);
        reset_send_buffer(pclient);
        return MQTT_UNSUBSCRIBE_PACKET_ERROR;
    }

    if(mc_send_packet(pclient, pclient->buf_send, len, &timer) != SUCCESS_RETURN){
        mqtt_err("mc_send_packet failed");
        reset_send_buffer(pclient);
        return MQTT_NETWORK_ERROR;
    }
    reset_send_buffer(pclient);
    return SUCCESS_RETURN;
}


int mqtt_client_set_conn_event_notify_cb(mqtt_client_t *pclient, mqtt_client_conn_event_notify_cb notify_cb, void *cb_param)
{
    if(pclient == NULL || notify_cb == NULL){
        mqtt_err("mqtt_client_set_conn_event_notify_cb failed");
        return NULL_VALUE_ERROR;
    }

    pclient->conn_event_notify_cb = notify_cb;
    pclient->conn_event_notify_cb_param = cb_param;

    return SUCCESS_RETURN;
}


static int mc_conn_event_notify(mqtt_client_t *pclient, mqtt_client_conn_event_e event)
{
    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    if(pclient->conn_event_notify_cb != NULL){
        pclient->conn_event_notify_cb(pclient, event, pclient->conn_event_notify_cb_param);
    }

    return SUCCESS_RETURN;
}



static int MQTTDisconnect(mqtt_client_t *pclient)
{
    int rc = FAIL_RETURN;
    int len = 0;
    utils_time_t timer;

    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    if(alloc_send_buffer(pclient, 0) < 0){
        mqtt_err("alloc send buffer failed");
        return FAIL_RETURN;
    }

    len = MQTTSerialize_disconnect((unsigned char *)pclient->buf_send, pclient->buf_size_send);
    if(len <= 0){
        mqtt_err("MQTTSerialize_disconnect failed, len=%d", len);
        reset_send_buffer(pclient);
        return FAIL_RETURN;
    }

    utils_time_init(&timer);
    utils_time_countdown_ms(&timer, pclient->request_timeout_ms);

    if(len > 0){
        rc = mc_send_packet(pclient, pclient->buf_send, len, &timer);
    }

    reset_send_buffer(pclient);

    return rc;
}



static int mc_rte_job_destroy_client(mqtt_client_t *pclient)
{
    int rc = -1;

    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    // 设置连接状态为初始化
    mc_set_client_state(pclient, MC_STATE_INVALID);

    // 释放client各种资源
    // 遍历qos1_msg_hashmap_table,删除所有节点并释放内存
    mqtt_qos1_msg_hashmap_node_t *node, *next_node;
    HASH_ITER(hh, pclient->qos1_msg_hashmap_table, node, next_node){
        HASH_DEL(pclient->qos1_msg_hashmap_table, node);
        mqtt_free(node->buf);
        mqtt_free(node);
    }

    // 遍历subscribe_hashmap_table,删除所有节点并释放内存
    mqtt_subscribe_hashmap_node_t *sub_node, *sub_next_node;
    HASH_ITER(hh, pclient->subscribe_hashmap_table, sub_node, sub_next_node){
        HASH_DEL(pclient->subscribe_hashmap_table, sub_node);
        mqtt_free(sub_node->topic_name);
        mqtt_free(sub_node);
    }

    // 销毁锁
    port_mutex_destroy(pclient->lock_generic);

    /*
    // 回调通知销毁成功
    if(pclient->destroy_finished_notify_cb != NULL){
        pclient->destroy_finished_notify_cb(pclient, pclient->destroy_finished_notify_cb_param);
    }
        */

    // 释放client内存
    mqtt_free(pclient);
    pclient = NULL;
    mqtt_info("mqtt client destroy success.");

    return 0;
}


static int mc_attempt_disconnect(mqtt_client_t *pclient, mqtt_client_rte_job_info_t *job_info)
{
    int rc;
    // 查看当前连接状态，如果是已连接状态，需要先断开连接
    if(mc_get_client_state(pclient) == MC_STATE_CONNECTED){
        rc = MQTTDisconnect(pclient);
        mqtt_debug("MQTTDisconnect, rc=%d", rc);
    }

    // 关闭tcp连接
    pclient->ipstack.disconnect(&pclient->ipstack);

    // 设置连接状态为初始化
    mc_set_client_state(pclient, MC_STATE_INVALID);

    // 触发连接断开事件通知
    mc_run_rte_job_conn_event_notify(pclient, MC_CONN_EVENT_DISCONNECTED);

    return SUCCESS_RETURN;
}



static int mc_rte_poll(mqtt_client_t *pclient)
{
    mqtt_client_rte_job_info_t *job_info;
    mqtt_topic_info_t *topic_info;
    mqtt_subscribe_hashmap_node_t *sub_topic_node;
    char perr;
    int rc = 0;

    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    job_info = (mqtt_client_rte_job_info_t *)cQRcv(pclient->rte_job_queue, &perr);
    if(job_info == NULL){
        return SUCCESS_RETURN;
    }

    switch(job_info->job_type){
        case MC_JOB_TYPE_PUBLISH:
            topic_info = job_info->topic_info;
            rc = MQTTPublish(pclient, topic_info);
            // 重要，必须释放topic_info，避免内存泄漏
            mqtt_topic_info_free(topic_info);
            if(rc != SUCCESS_RETURN && rc == MQTT_NETWORK_ERROR){
                mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
            }
            break;
        case MC_JOB_TYPE_SUB_MSG_NOTIFY:
            topic_info = job_info->topic_info;
            // 使用 topic name作为key从 sub hashmap 中查找节点
            HASH_FIND_STR(pclient->subscribe_hashmap_table, topic_info->topic_name, sub_topic_node);
            if(sub_topic_node != NULL){
                if(sub_topic_node->topic_callback != NULL){
                    sub_topic_node->topic_callback(pclient, topic_info, sub_topic_node->cb_param);
                }
            }

            mqtt_topic_info_free(topic_info);
            break;
        case MC_JOB_TYPE_UNSUB:
            rc = MQTTUnsubscribe(pclient, job_info->unsub_topic_name);
            if(rc != SUCCESS_RETURN && rc == MQTT_NETWORK_ERROR){
                mc_set_client_state(pclient, MC_STATE_DISCONNECTED);
            }
            mqtt_free(job_info->unsub_topic_name);
            break;
        case MC_JOB_TYPE_CONN_EVENT_NOTIFY:
            mc_conn_event_notify(pclient, job_info->conn_event);
            // 此处不需要释放job info 内部信息
            break;
        case MC_JOB_TYPE_ATTEMPT_DISCONNECTING:
            mc_attempt_disconnect(pclient, job_info);
            break;
        case MC_JOB_TYPE_DESTROY_CLIENT:
            mc_rte_job_destroy_client(pclient);
            break;
        default:
            break;
    }

    // 释放job info
    mqtt_free(job_info);
    return SUCCESS_RETURN;
}




int mqtt_client_poll(mqtt_client_t *pclient, int timeout_ms)
{
    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    if(timeout_ms <= 10){
        timeout_ms = 10;
    }

    pclient->cycle_timeout_ms = timeout_ms;
    // 执行保活逻辑，发送心跳包，检查连接状态，断开重连
    mc_keepalive(pclient);

    // 处理接收数据 todo
    mc_cycle_recv(pclient);

    // rte job 处理
    mc_rte_poll(pclient);

    // resubcribe
    mc_resubscribe_proc(pclient);

    return 0;
}


int mqtt_client_publish(mqtt_client_t *pclient, const char *topic_name, mqtt_qos_t qos, unsigned char *data, int len)
{
    int rc = FAIL_RETURN;
    mqtt_client_rte_job_info_t *job_info;
    mqtt_topic_info_t *topic_msg;
    unsigned short packet_id = 0;
    if(pclient == NULL || topic_name == NULL || data == NULL || len <= 0){
        
        return NULL_VALUE_ERROR;
    }

    if(mc_get_client_state(pclient) != MC_STATE_CONNECTED){
        return MQTT_STATE_ERROR;
    }

#if CONFIG_MQTT_ONLY_SUPPORT_QOS0
    qos = MQTT_QOS0;
#endif

    if(qos != MQTT_QOS0){
        packet_id = mc_get_next_packet_id(pclient);
    }

    job_info = (mqtt_client_rte_job_info_t *)port_malloc(sizeof(mqtt_client_rte_job_info_t));
    if(job_info == NULL){
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }

    topic_msg = mqtt_topic_info_create(packet_id, qos, 0, 0, topic_name, len, data);
    if(topic_msg == NULL){
        mqtt_err("malloc failed.");
        port_free(job_info);
        return FAIL_RETURN;
    }

    job_info->job_type = MC_JOB_TYPE_PUBLISH;
    job_info->topic_info = topic_msg;

    cQPost(pclient->rte_job_queue, (void *)job_info);
    
    return 0;
}



static mqtt_subscribe_hashmap_node_t *mc_get_subscribe_hashmap_node(mqtt_client_t *pclient, char *topic_name)
{
    mqtt_subscribe_hashmap_node_t *node = NULL;

    if(pclient == NULL || topic_name == NULL){
        return NULL;
    }

    HASH_FIND_STR(pclient->subscribe_hashmap_table, topic_name, node);

    return node;
}



int mqtt_client_subscribe(mqtt_client_t *pclient, const char *topic_name, mqtt_qos_t qos,
                mqtt_client_sub_msg_notify_cb topic_callback,
                void *pcontext)
{
    mc_state_t  currentState = MC_STATE_INVALID;
    unsigned short packet_id = 0;
    int rc;
    mqtt_subscribe_hashmap_node_t *node = NULL;
    

    if(pclient == NULL || topic_name == NULL || topic_callback == NULL){
        mqtt_err("param is null.");
        return NULL_VALUE_ERROR;
    }

    // 校验topic名称是否合法
    if(mc_check_topic_name(topic_name, 0) != SUCCESS_RETURN){
        mqtt_err("topic_name is invalid.");
        return MQTT_TOPIC_FORMAT_ERROR;
    }

    // 查看该topic是否重复订阅，如果重复订阅，则覆盖订阅参数
    node = mc_get_subscribe_hashmap_node(pclient, (char *)topic_name);
    if(node != NULL){
        if(node->qos != qos){
            mqtt_info("topic_name=%s, qos=%d is already subscribed.", topic_name, qos);
            node->qos = qos;
            node->sub_succ = 0;   // 重新订阅，需要重新订阅
        }
        node->topic_callback = topic_callback;
        node->cb_param = pcontext;
        return SUCCESS_RETURN;
    }

    // 申请创建订阅节点
    node = (mqtt_subscribe_hashmap_node_t *)port_malloc(sizeof(mqtt_subscribe_hashmap_node_t));
    if(node == NULL){
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }

    memset(node, 0, sizeof(mqtt_subscribe_hashmap_node_t));
    node->topic_name = port_malloc(strlen(topic_name) + 1);
    if(node->topic_name == NULL){
        port_free(node);
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }
    strcpy(node->topic_name, topic_name);
    node->qos = qos;
    node->topic_callback = topic_callback;
    node->cb_param = pcontext;
    node->sub_succ = 0;
    utils_time_init(&node->sub_start_time);
    HASH_ADD_KEYPTR(hh, pclient->subscribe_hashmap_table, node->topic_name, strlen(node->topic_name), node);

    return SUCCESS_RETURN;
}


int mqtt_client_unsubscribe(mqtt_client_t *pclient, const char *topic_name)
{
    mc_state_t  currentState = MC_STATE_INVALID;
    mqtt_subscribe_hashmap_node_t *sub_node = NULL;
    mqtt_client_rte_job_info_t *job_info;
    char *unsub_topic_name;

    if(pclient == NULL || topic_name == NULL){
        mqtt_err("param is null.");
        return NULL_VALUE_ERROR;
    }

    currentState = mc_get_client_state(pclient);
    if(currentState != MC_STATE_CONNECTED){
        mqtt_err("mqtt client is not connected.");
        return MQTT_STATE_ERROR;
    }

    // 通过topic name，查找订阅节点是否存在
    HASH_FIND_STR(pclient->subscribe_hashmap_table, topic_name, sub_node);
    if(sub_node == NULL){
        mqtt_err("topic_name=%s is not subscribed.", topic_name);
    }else{
        HASH_DEL(pclient->subscribe_hashmap_table, sub_node);
        mqtt_free(sub_node->topic_name);
        mqtt_free(sub_node);
    }

    // 创建解订阅 rte job
    job_info = (mqtt_client_rte_job_info_t *)mqtt_malloc(sizeof(mqtt_client_rte_job_info_t));
    if(job_info == NULL){
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }

    unsub_topic_name = (char *)mqtt_malloc(strlen(topic_name) + 1);
    if(unsub_topic_name == NULL){
        mqtt_free(job_info);
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }

    strcpy(unsub_topic_name, topic_name);
    job_info->job_type = MC_JOB_TYPE_UNSUB;
    job_info->unsub_topic_name = unsub_topic_name;

    cQPost(pclient->rte_job_queue, (void *)job_info);

    return SUCCESS_RETURN;
}


int mqtt_client_disconnect(mqtt_client_t *pclient)
{
    mqtt_client_rte_job_info_t *job_info;
    if(pclient == NULL){
        mqtt_err("param is null.");
        return NULL_VALUE_ERROR;
    }

    // 创建disconnect rte job
    job_info = (mqtt_client_rte_job_info_t *)mqtt_malloc(sizeof(mqtt_client_rte_job_info_t));
    if(job_info == NULL){
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }
    memset(job_info, 0, sizeof(mqtt_client_rte_job_info_t));
    job_info->job_type = MC_JOB_TYPE_ATTEMPT_DISCONNECTING;
    // 不需要参数

    cQPost(pclient->rte_job_queue, (void *)job_info);

    return SUCCESS_RETURN;
}



int mqtt_client_destroy(mqtt_client_t *pclient)
{
    mqtt_client_rte_job_info_t *job_info;
    if(pclient == NULL){
        return NULL_VALUE_ERROR;
    }

    // 断开连接
    mqtt_client_disconnect(pclient);

    // 创建销毁client rte job
    job_info = (mqtt_client_rte_job_info_t *)mqtt_malloc(sizeof(mqtt_client_rte_job_info_t));
    if(job_info == NULL){
        mqtt_err("malloc failed.");
        return FAIL_RETURN;
    }

    job_info->job_type = MC_JOB_TYPE_DESTROY_CLIENT;
    // 不需要参数

    cQPost(pclient->rte_job_queue, (void *)job_info);

    return SUCCESS_RETURN;
}