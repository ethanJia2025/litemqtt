#!/bin/bash
set -e

# 定义颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 输出目录
OUT_DIR=out

# 默认构建类型
BUILD_TYPE="Release"
HOST=""

# 显示帮助信息函数
show_help() {
    echo -e "${BLUE}用法:${NC} $0 [选项]"
    echo "选项:"
    echo "  --with-tls=0|1    配置是否启用TLS支持"
    echo "  --debug           启用调试模式构建 (包含-g)"
    echo "  --host=TRIPLE     指定交叉编译工具链前缀 (如 arm-linux-gnueabi)"
    echo "  --help            显示此帮助信息"
    echo -e "\n示例:"
    echo "  $0 --with-tls=1   启用TLS支持构建"
    echo "  $0 --with-tls=0   禁用TLS支持构建"
    echo "  $0 --with-tls=1 --debug  启用TLS支持和调试信息"
    echo "  $0 --with-tls=1 --host=arm-linux-gnueabi  为ARM平台构建"
}

# 检查交叉编译工具链是否存在
check_cross_compiler() {
    local toolchain_prefix="$1"
    local gcc_path=$(which "${toolchain_prefix}-gcc" 2>/dev/null)
    
    if [ -z "$gcc_path" ]; then
        echo -e "${RED}错误:${NC} 未找到交叉编译器 '${toolchain_prefix}-gcc'"
        echo -e "请确保已安装相应的交叉编译工具链并已添加到PATH中。"
        return 1
    fi
    
    echo -e "${GREEN}已找到交叉编译器:${NC} ${gcc_path}"
    return 0
}

# 如果没有参数，显示帮助信息并退出
if [ "$#" -eq 0 ]; then
    echo -e "${RED}错误:${NC} 必须提供参数指定构建配置"
    show_help
    exit 1
fi

# 解析命令行参数
for i in "$@"; do
  case $i in
    --with-tls=*)
      WITH_TLS="${i#*=}"
      shift
      ;;
    --host=*)
      HOST="${i#*=}"
      shift
      ;;
    --debug)
      BUILD_TYPE="Debug"
      shift
      ;;
    --help)
      show_help
      exit 0
      ;;
    *)
      # 未知参数
      echo -e "${RED}错误:${NC} 未知参数 '$i'"
      show_help
      exit 1
      ;;
  esac
done

# 验证TLS参数值
if [ "$WITH_TLS" != "0" ] && [ "$WITH_TLS" != "1" ]; then
    echo -e "${RED}错误:${NC} --with-tls参数必须是0或1"
    show_help
    exit 1
fi

# 转换成CMake选项格式
if [ "$WITH_TLS" = "0" ]; then
  TLS_OPTION=OFF
  TLS_STATUS="已禁用"
else
  TLS_OPTION=ON
  TLS_STATUS="已启用"
fi

echo -e "${BLUE}========== MQTT客户端构建开始 ==========${NC}"
echo -e "TLS支持: ${YELLOW}${TLS_STATUS}${NC}"
echo -e "构建类型: ${YELLOW}${BUILD_TYPE}${NC}"

# 检查交叉编译设置
CROSS_COMPILE_OPTIONS=""
if [ -n "$HOST" ]; then
    echo -e "目标平台: ${YELLOW}${HOST}${NC}"
    # 检查交叉编译工具是否存在
    if ! check_cross_compiler "$HOST"; then
        exit 1
    fi
    # 设置CMake交叉编译选项
    CROSS_COMPILE_OPTIONS="-DCMAKE_C_COMPILER=${HOST}-gcc -DCMAKE_CXX_COMPILER=${HOST}-g++ -DCMAKE_SYSTEM_NAME=Linux"
    echo -e "使用交叉编译工具链: ${YELLOW}${HOST}${NC}"
else
    echo -e "目标平台: ${YELLOW}本地平台${NC}"
fi

# 清理旧的构建目录
echo -e "\n${BLUE}[步骤 1/5]${NC} 清理旧的构建目录..."
rm -rf ${OUT_DIR}

# 创建并进入构建目录
echo -e "\n${BLUE}[步骤 2/5]${NC} 创建构建目录..."
mkdir -p ${OUT_DIR}
cd ${OUT_DIR}

# 配置CMake
echo -e "\n${BLUE}[步骤 3/5]${NC} 配置CMake，TLS=${YELLOW}${TLS_OPTION}${NC}..."
cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DENABLE_TLS=${TLS_OPTION} ${CROSS_COMPILE_OPTIONS} ..

# 执行构建
echo -e "\n${BLUE}[步骤 4/5]${NC} 执行编译..."
cmake --build . -- -j$(nproc)

# 清理CMake相关文件，保留构建产物
echo -e "\n${BLUE}[步骤 5/5]${NC} 清理CMake相关文件..."

# 首先确认构建产物存在
if [ ! -f "bin/demo_mqtt_client" ]; then
    echo -e "${YELLOW}警告:${NC} 未找到可执行文件 bin/demo_mqtt_client，跳过清理步骤"
else
    # 使用更安全的方法清理CMake文件，保留构建产物
    echo -e "清理CMake文件，保留bin/, include/, lib/目录..."
    
    # 确保这些目录存在
    mkdir -p bin lib include
    
    # 删除特定的CMake文件而不是整个目录
    find . -name "CMake*" -not -path "./bin/*" -not -path "./lib/*" -not -path "./include/*" | xargs rm -rf 2>/dev/null || true
    find . -name "*.cmake" -not -path "./bin/*" -not -path "./lib/*" -not -path "./include/*" | xargs rm -rf 2>/dev/null || true
    find . -name "Makefile" -not -path "./bin/*" -not -path "./lib/*" -not -path "./include/*" | xargs rm -f 2>/dev/null || true
    
    # 删除其他不需要的目录和文件，但保留bin/、lib/、include/
    find . -maxdepth 1 -not -name "bin" -not -name "lib" -not -name "include" -not -name "." | xargs rm -rf 2>/dev/null || true
    
    echo -e "${GREEN}清理完成，已保留构建产物${NC}"
fi

# 返回上层目录
cd ..

echo -e "\n${GREEN}=============================================================${NC}"
echo -e "${GREEN}构建成功完成！${NC}"

# 显示平台信息
PLATFORM_INFO=""
if [ -n "$HOST" ]; then
    PLATFORM_INFO=" (${HOST}平台)"
fi

echo -e "\n${BLUE}生成文件:${NC}"
echo -e "- 静态库: ${YELLOW}${OUT_DIR}/lib/libmqtt_client.a${PLATFORM_INFO}${NC}"
echo -e "- 动态库: ${YELLOW}${OUT_DIR}/lib/libmqtt_client.so${PLATFORM_INFO}${NC}"
echo -e "- 头文件: ${YELLOW}${OUT_DIR}/include/mqtt_client.h${NC}"
echo -e "- 演示程序: ${YELLOW}${OUT_DIR}/bin/demo_mqtt_client${PLATFORM_INFO}${NC}"

echo -e "\n${BLUE}构建配置信息:${NC}"
echo -e "- 目标平台: ${YELLOW}${HOST:-本地平台}${NC}"
echo -e "- TLS支持: ${YELLOW}${TLS_STATUS}${NC}"
echo -e "- 构建类型: ${YELLOW}${BUILD_TYPE}${NC}"
if [ "$WITH_TLS" = "1" ]; then
  echo -e "- 功能: 支持${YELLOW}TLS加密连接${NC}和普通TCP连接"
  echo -e "- 安全性: 提供数据加密和服务器身份验证"
else
  echo -e "- 功能: 仅支持${YELLOW}普通TCP连接${NC}"
  echo -e "- 安全性: 不提供数据加密，适用于内网环境"
fi
echo -e "${GREEN}=============================================================${NC}"