cmake_minimum_required(VERSION 3.10)
project(litemqtt VERSION 1.0.0 LANGUAGES C)

# 设置C语言标准为C99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# TLS选项
option(ENABLE_TLS "Enable TLS support" ON)

# 根据选项设置编译参数
if(ENABLE_TLS)
    add_definitions(-DCONFIG_SUPPORT_TLS)
    message(STATUS "TLS支持: 已启用")
else()
    message(STATUS "TLS支持: 已禁用")
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(HEADER_OUTPUT_DIR ${CMAKE_BINARY_DIR}/include)

# 头文件包含路径
include_directories(src)

# 收集MQTT核心源文件 - 只包含src目录
file(GLOB MQTT_SOURCES "src/*.c")

# 创建静态库
add_library(mqtt_client_static STATIC ${MQTT_SOURCES})
set_target_properties(mqtt_client_static PROPERTIES 
    OUTPUT_NAME mqtt_client
    CLEAN_DIRECT_OUTPUT 1
)

# 创建动态库
add_library(mqtt_client_shared SHARED ${MQTT_SOURCES})
set_target_properties(mqtt_client_shared PROPERTIES 
    OUTPUT_NAME mqtt_client
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CLEAN_DIRECT_OUTPUT 1
)

# 创建头文件目录并复制头文件
add_custom_target(copy_headers ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${HEADER_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/src/mqtt_client.h ${HEADER_OUTPUT_DIR}/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/src/mqtt_client_err_code.h ${HEADER_OUTPUT_DIR}/
    COMMENT "正在复制头文件到 ${HEADER_OUTPUT_DIR}"
    VERBATIM
)

# 添加依赖关系
add_dependencies(mqtt_client_static copy_headers)
add_dependencies(mqtt_client_shared copy_headers)

# 构建演示程序 - 这里需要包含平台适配代码
if(ENABLE_TLS)
    # 添加平台适配头文件路径
    include_directories(port port/Linux port/mbedtls-v2.28/include)
    
    # 收集平台适配源文件
    file(GLOB PORT_BASE "port/Linux/port_base.c")
    file(GLOB PORT_TLS_SOURCES "port/Linux/port_tcp_ssl.c")
    file(GLOB_RECURSE MBEDTLS_SOURCES "port/mbedtls-v2.28/library/*.c")
    
    # 创建演示程序
    add_executable(demo_mqtt_client 
        test/demo_mqtt_client.c
        ${PORT_BASE}
        ${PORT_TLS_SOURCES}
        ${MBEDTLS_SOURCES}
    )
    
    # 链接库和所需依赖
    target_link_libraries(demo_mqtt_client 
        mqtt_client_static
        pthread m rt dl
    )
else()
    # 添加基本平台适配头文件路径
    include_directories(port port/Linux)
    
    # 只收集基本TCP实现
    file(GLOB PORT_BASE "port/Linux/port_base.c")
    
    # 创建演示程序
    add_executable(demo_mqtt_client 
        test/demo_mqtt_client.c
        ${PORT_BASE}
    )
    
    # 链接库和所需依赖
    target_link_libraries(demo_mqtt_client 
        mqtt_client_static
        pthread m rt dl
    )
endif()

message(STATUS "项目: ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "TLS支持: ${ENABLE_TLS}")
message(STATUS "输出目录: ${CMAKE_BINARY_DIR}")
message(STATUS "静态库: ${CMAKE_BINARY_DIR}/lib/libmqtt_client.a")
message(STATUS "动态库: ${CMAKE_BINARY_DIR}/lib/libmqtt_client.so")
message(STATUS "演示程序: ${CMAKE_BINARY_DIR}/bin/demo_mqtt_client")