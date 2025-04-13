# Lite mqtt client
[英文说明](README.md)

# 项目概览
- 一句话定位：轻量级、高性能的ANSI-C MQTT客户端协议栈，支持TLS，断开重连、断开自动订阅，适用嵌入式生产环境使用。
- 核心价值：极少外部依赖，内存占用 < 2.2KByte,支持主流 MQTT 3.1.1协议版本。
- 适用场景：IOT设备、工业控制、智能家居等。

# 核心特性
- 核心功能支持：支持MQTT 3.1.1协议版本，支持TLS，支持publish、subscribe、unsubscribe、ping等操作，支持断开重连、断开自动订阅。
- 低资源占用：内存占用 < 2.2KByte，支持多线程，支持多实例。
- Qos：目前仅支持Qos0，Qos1，对资源比较敏感的使用场景，可配置使用仅支持Qos0。
- 断开重连：支持断开重连，断开重连时，自动订阅已订阅的topic（可配置）。
- 跨平台：支持Linux/RTOS/Android/IOS等平台。
- 安全传输：可选集成mbedTLS，API原生支持单/双向TLS认证。
- 内存安全：通过asan、valgrind等工具检测内存安全，无内存泄漏、内存溢出等问题。
- 构建简单：通过构建脚本，一键构建。

# 快速开始
```shell
# 1. 进入test目录
cd test

# 2. 修改demo_mqtt_client.c中的SERVER_ADDR为您的MQTT Broker服务器地址

# 3. 修改demo_mqtt_client.c中的SERVER_PORT为您的MQTT Broker服务器端口(如果您的mqtt broker使用默认emqx的端口，则无需修改)

# 4. 修改demo_mqtt_client.c中的client相关参数为您的client相关参数.

# 5. 构建mqtt (不支持TLS)库、demo程序。
./build.sh --with-tls=0

# 6. 运行demo程序
./out/bin/demo_mqtt_client
```

# 构建说明
**用法：** 
```shell
./build.sh [options]
```
选项：
* --with-tls=0|1    配置是否启用TLS支持，0-不支持，1-支持
* --debug           启用调试模式构建 (包含-g)
* --host=TRIPLE     指定交叉编译工具链前缀 (如 arm-linux-gnueabi)，假如不添加此选项，默认为gcc
* --help            显示此帮助信息

**示例：**
```shell
  ./build.sh --with-tls=1   启用TLS支持构建,gcc编译
  ./build.sh --with-tls=0   禁用TLS支持构建,gcc编译
  ./build.sh --with-tls=1 --debug  启用TLS支持和调试信息
  ./build.sh --with-tls=1 --host=arm-linux-gnueabi  使用arm-linux-gnueabi交叉编译，支持TLS
```

**特别注意：**
1. 构建生成的静态库libmqtt_client.a、动态库libmqtt_client.so.1.0.0，并不会包含port/下的文件，因为port/下的文件是平台相关的，需要适配，应用APP需要适配这些函数，并集成到工程中，与libmqtt_client.a或libmqtt_client.so.1.0.0一起编译。
2. 如果想要源码集成，需要集成src、port/下的文件集成到工程项目，根据平台编译，需要适配port/下的文件。

# 南向适配API List
| API名称               | 功能                        | 是否必须        |
|-----------------------|----------------------------|-----------------|
| port_malloc           | 内存申请                    | 是              |
| port_free             | 内存释放                    | 是              |
| port_mutex_create     | 创建互斥锁                  | 可选            |
| port_mutex_destroy    | 销毁互斥锁                  | 可选            |                
| port_mutex_lock       | 阻塞式加锁                  | 可选            |
| port_mutex_unlock     | 释放锁                      | 可选            |
| port_printf           | 打印                        | 是              |
| port_sleep_ms         | 休眠等待                    | 是              |
| port_uptime_ms        | 获取系统启动后经过的毫秒值    | 是              |
| port_tcp_establish    | 建立tcp连接                 | 是              |
| port_tcp_read         | 同步读取tcp数据             | 是              |
| port_tcp_write        | 同步写入tcp数据             | 是              |
| port_tcp_destroy      | 销毁tcp连接                 | 是              |
| port_ssl_establish    | 建立ssl连接                 | 使用TLS时必选    |
| port_ssl_read         | 同步从ssl读取数据           | 使用TLS时必选     |
| port_ssl_write        | 同步向ssl写入数据           | 使用TLS时必选     |
| port_ssl_destroy      | 销毁ssl连接                 | 使用TLS时必选    |






