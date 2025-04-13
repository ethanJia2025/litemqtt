# Lite MQTT Client

[中文说明](README.zh.md)

# Project Overview
- Brief description: A lightweight, high-performance ANSI-C MQTT client protocol stack with TLS support, automatic reconnection, and subscription recovery, suitable for embedded production environments.
- Core value: Minimal external dependencies, memory footprint < 2.2KByte, supports mainstream MQTT 3.1.1 protocol version.
- Use cases: IoT devices, industrial control, smart home systems, etc.

# Core Features
- Core functionality: Supports MQTT 3.1.1 protocol, TLS, publish, subscribe, unsubscribe, ping operations, automatic reconnection and resubscription.
- Low resource consumption: Memory footprint < 2.2KByte, multi-threading support, multiple instance support.
- QoS: Currently supports QoS0 and QoS1. For resource-constrained environments, can be configured to support only QoS0.
- Reconnection: Supports automatic reconnection with subscription recovery (configurable).
- Cross-platform: Supports Linux, RTOS, Android, iOS and other platforms.
- Secure transport: Optional mbedTLS integration, API natively supports one-way/two-way TLS authentication.
- Memory safety: Verified with tools like ASAN and Valgrind to ensure no memory leaks or buffer overflows.
- Simple build process: One-click build through build scripts.

# Quick Start
```shell
# 1. Enter the test directory
cd test

# 2. Modify SERVER_ADDR in demo_mqtt_client.c to your MQTT Broker server address

# 3. Modify SERVER_PORT in demo_mqtt_client.c to your MQTT Broker server port (no need to modify if your mqtt broker uses the default emqx port)

# 4. Modify client-related parameters in demo_mqtt_client.c to your client parameters

# 5. Build mqtt library (without TLS) and demo program
./build.sh --with-tls=0

# 6. Run the demo program
./out/bin/demo_mqtt_client
```

# Build Instructions
**Usage:** 
```shell
./build.sh [options]
```
Options:
* --with-tls=0|1    Configure whether to enable TLS support, 0-disabled, 1-enabled
* --debug           Enable debug mode build (includes -g)
* --host=TRIPLE     Specify cross-compilation toolchain prefix (e.g., arm-linux-gnueabi), defaults to gcc if not specified
* --help            Display this help information

**Examples:**
```shell
  ./build.sh --with-tls=1   Build with TLS support, using gcc
  ./build.sh --with-tls=0   Build without TLS support, using gcc
  ./build.sh --with-tls=1 --debug  Build with TLS support and debug information
  ./build.sh --with-tls=1 --host=arm-linux-gnueabi  Cross-compile using arm-linux-gnueabi with TLS support
```

**Important Notes:**
1. The generated static library libmqtt_client.a and dynamic library libmqtt_client.so.1.0.0 do not include files from the port/ directory. These files are platform-specific and need to be adapted. Application developers need to adapt these functions and integrate them into their projects, compiling them together with libmqtt_client.a or libmqtt_client.so.1.0.0.
2. For source code integration, include the files from src/ and port/ directories in your project, adapting the port/ files according to your platform.

# Southbound API Adaptation List
| API Name             | Function                     | Required        |
|-----------------------|----------------------------|-----------------|
| port_malloc           | Memory allocation          | Yes             |
| port_free             | Memory deallocation        | Yes             |
| port_mutex_create     | Create mutex               | Optional        |
| port_mutex_destroy    | Destroy mutex              | Optional        |                
| port_mutex_lock       | Blocking lock              | Optional        |
| port_mutex_unlock     | Release lock               | Optional        |
| port_printf           | Print                      | Yes             |
| port_sleep_ms         | Sleep                      | Yes             |
| port_uptime_ms        | Get system uptime in ms    | Yes             |
| port_tcp_establish    | Establish TCP connection   | Yes             |
| port_tcp_read         | Synchronously read TCP data| Yes             |
| port_tcp_write        | Synchronously write TCP data| Yes            |
| port_tcp_destroy      | Destroy TCP connection     | Yes             |
| port_ssl_establish    | Establish SSL connection   | Required for TLS|
| port_ssl_read         | Synchronously read from SSL| Required for TLS|
| port_ssl_write        | Synchronously write to SSL | Required for TLS|
| port_ssl_destroy      | Destroy SSL connection     | Required for TLS|