#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "mqtt_client.h"
#include <sys/time.h>



#define SERVER_ADDR         "192.168.6.128"

#ifdef CONFIG_SUPPORT_TLS
#define SERVER_PORT         8883

const char *emqx_ca_cert = \
{
    \
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDUTCCAjmgAwIBAgIJAPPYCjTmxdt/MA0GCSqGSIb3DQEBCwUAMD8xCzAJBgNV\r\n" \
    "BAYTAkNOMREwDwYDVQQIDAhoYW5nemhvdTEMMAoGA1UECgwDRU1RMQ8wDQYDVQQD\r\n" \
    "DAZSb290Q0EwHhcNMjAwNTA4MDgwNjUyWhcNMzAwNTA2MDgwNjUyWjA/MQswCQYD\r\n" \
    "VQQGEwJDTjERMA8GA1UECAwIaGFuZ3pob3UxDDAKBgNVBAoMA0VNUTEPMA0GA1UE\r\n" \
    "AwwGUm9vdENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzcgVLex1\r\n" \
    "EZ9ON64EX8v+wcSjzOZpiEOsAOuSXOEN3wb8FKUxCdsGrsJYB7a5VM/Jot25Mod2\r\n" \
    "juS3OBMg6r85k2TWjdxUoUs+HiUB/pP/ARaaW6VntpAEokpij/przWMPgJnBF3Ur\r\n" \
    "MjtbLayH9hGmpQrI5c2vmHQ2reRZnSFbY+2b8SXZ+3lZZgz9+BaQYWdQWfaUWEHZ\r\n" \
    "uDaNiViVO0OT8DRjCuiDp3yYDj3iLWbTA/gDL6Tf5XuHuEwcOQUrd+h0hyIphO8D\r\n" \
    "tsrsHZ14j4AWYLk1CPA6pq1HIUvEl2rANx2lVUNv+nt64K/Mr3RnVQd9s8bK+TXQ\r\n" \
    "KGHd2Lv/PALYuwIDAQABo1AwTjAdBgNVHQ4EFgQUGBmW+iDzxctWAWxmhgdlE8Pj\r\n" \
    "EbQwHwYDVR0jBBgwFoAUGBmW+iDzxctWAWxmhgdlE8PjEbQwDAYDVR0TBAUwAwEB\r\n" \
    "/zANBgkqhkiG9w0BAQsFAAOCAQEAGbhRUjpIred4cFAFJ7bbYD9hKu/yzWPWkMRa\r\n" \
    "ErlCKHmuYsYk+5d16JQhJaFy6MGXfLgo3KV2itl0d+OWNH0U9ULXcglTxy6+njo5\r\n" \
    "CFqdUBPwN1jxhzo9yteDMKF4+AHIxbvCAJa17qcwUKR5MKNvv09C6pvQDJLzid7y\r\n" \
    "E2dkgSuggik3oa0427KvctFf8uhOV94RvEDyqvT5+pgNYZ2Yfga9pD/jjpoHEUlo\r\n" \
    "88IGU8/wJCx3Ds2yc8+oBg/ynxG8f/HmCC1ET6EHHoe2jlo8FpU/SgGtghS1YL30\r\n" \
    "IWxNsPrUP+XsZpBJy/mvOhE5QXo6Y35zDqqj8tI7AGmAWu22jg==\r\n" \
    "-----END CERTIFICATE-----"
};

#else
#define SERVER_PORT         1883
#endif

#define USER_NAME           "mydevice"
#define PASSWORD            "12345678"
#define CLIENT_ID           "A1B2C3D4E5F6"
#define TEST_PUB_TOPIC      "testtopic/A1B2C3D4E5F6/up"
#define TEST_SUB_TOPIC      "testtopic/A1B2C3D4E5F6/down"



void mc_conn_event_notify_cb(mqtt_client_t *pclient, mqtt_client_conn_event_e result, void *cb_param)
{
    printf("mc_conn_event_notify:%d, cb_param:%s\n", result, (char *)cb_param);
}


void mqtt_client_test_sub_msg_notify_cb(mqtt_client_t *pclient, 
                                mqtt_topic_info_t *msg,
                                void *cb_param)
{
    printf("mqtt_client_test_sub_msg_notify_cb\n");
    printf("topic_name: %s\n", msg->topic_name);
    printf("payload: %s\n", msg->payload);
    printf("payload_len: %d\n", msg->payload_len);
}

extern unsigned int port_memory_usage(void);


int main(void)
{
    printf("Hello, World!\n");
    const char *test_cb_param = "this is test cb param";
    char *test_pub_msg_buf[128];

    int rc, cnt = 0, tick = 0, unsub_trigger = 0;
    int len, trigger_cnt = 0;
    mqtt_client_t *my_client = NULL;
    mqtt_conn_config_t conn;
    mqtt_tls_config_t tls_config = {0};

    // mqtt
    conn.host = SERVER_ADDR;
    conn.port = SERVER_PORT;
    conn.client_id = CLIENT_ID;
    conn.username = USER_NAME;
    conn.password = PASSWORD;
    conn.keep_alive_interval_ms = 1000;

#ifdef CONFIG_SUPPORT_TLS
    conn.security_mode = MQTT_SEC_SSL_SERVER_AUTH;
    tls_config.ca_cert = emqx_ca_cert;
    tls_config.client_cert = NULL;
    tls_config.client_key = NULL;
    tls_config.client_key_pwd = NULL;
#else
    conn.security_mode = MQTT_SEC_NONE;
    tls_config.ca_cert = NULL;
    tls_config.client_cert = NULL;
    tls_config.client_key = NULL;
    tls_config.client_key_pwd = NULL;
#endif

    my_client = mqtt_client_new(&conn, &tls_config);

    if(my_client == NULL){
        return -1;
    }

    mqtt_client_set_conn_event_notify_cb(my_client, mc_conn_event_notify_cb, (void *)test_cb_param);


    do{
        rc = mqtt_client_connect(my_client);
        sleep(1);
    } while(rc != 0);

    if(rc == 0){
        printf("mqtt client connect success\n");
    }else{
        printf("mqtt client connect failed\n");
    }

    rc = mqtt_client_subscribe(my_client, TEST_SUB_TOPIC, MQTT_QOS0, mqtt_client_test_sub_msg_notify_cb, NULL);

    
    while(1){

        mqtt_client_poll(my_client, 100);
 
        if(tick++ > 30){
            tick = 0;

            memset(test_pub_msg_buf, 0, sizeof(test_pub_msg_buf));
            sprintf(test_pub_msg_buf, "hello world %d", cnt++);


            mqtt_client_publish(my_client, TEST_PUB_TOPIC, 
                            MQTT_QOS1,
                            (unsigned char *)test_pub_msg_buf, 
                            strlen(test_pub_msg_buf));

            
            printf("curr memory usage: %d\n", port_memory_usage());
        }

        trigger_cnt++;

        if(trigger_cnt  == 100){
            mqtt_client_disconnect(my_client);
        }

        if(trigger_cnt == 150){
            mqtt_client_connect(my_client);
        }

    }

    return 0;
}