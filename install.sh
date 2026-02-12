#!/bin/sh

# 设置颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 全局变量
BIN_PATH="/usr/local/bin/ddns"
WORK_DIR="/etc/ddns"
SYSTEMD_PATH="/etc/systemd/system/ddns.service"
OPENRC_PATH="/etc/init.d/ddns"

# 权限检查
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}错误: 必须使用 root 权限运行此脚本${NC}"
    exit 1
fi

# 环境检测函数
detect_env() {
    # 识别架构
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo "${RED}暂不支持的架构: ${ARCH_RAW}${NC}"; exit 1 ;;
    esac

    # 识别系统类型
    if [ -f /etc/alpine-release ]; then
        OS_TYPE="alpine"
    elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
        OS_TYPE="debian"
    else
        echo "${RED}仅支持 Debian/Ubuntu 或 Alpine 系统${NC}"
        exit 1
    fi
}

# 安装功能
do_install() {
    detect_env
    echo "${GREEN}开始安装 DDNS Master (${ARCH} / ${OS_TYPE})...${NC}"
    
    DOWNLOAD_URL="https://jht126.eu.org/https://github.com/jinhuaitao/ddns/releases/latest/download/ddns-linux-${ARCH}"
    
    mkdir -p ${WORK_DIR}
    echo "正在下载二进制文件..."
    if ! curl -L ${DOWNLOAD_URL} -o ${BIN_PATH}; then
        echo "${RED}下载失败，请检查网络${NC}"
        exit 1
    fi
    chmod +x ${BIN_PATH}

    if [ "${OS_TYPE}" = "debian" ]; then
        cat <<EOF > ${SYSTEMD_PATH}
[Unit]
Description=DDNS Master Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
ExecStart=${BIN_PATH}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ddns
        systemctl restart ddns
    elif [ "${OS_TYPE}" = "alpine" ]; then
        cat <<EOF > ${OPENRC_PATH}
#!/sbin/openrc-run
description="DDNS Master Service"
command="${BIN_PATH}"
command_background=true
directory="${WORK_DIR}"
pidfile="/run/ddns.pid"
restart_delay=5
depend() {
    need net
    after firewall
}
EOF
        chmod +x ${OPENRC_PATH}
        rc-update add ddns default
        rc-service ddns start
    fi
    echo "${GREEN}安装成功！管理地址: http://你的服务器IP:8080${NC}"
}

# 卸载功能
do_uninstall() {
    detect_env
    echo "${YELLOW}正在准备卸载 DDNS Master...${NC}"
    
    if [ "${OS_TYPE}" = "debian" ]; then
        systemctl stop ddns >/dev/null 2>&1
        systemctl disable ddns >/dev/null 2>&1
        rm -f ${SYSTEMD_PATH}
        systemctl daemon-reload
    elif [ "${OS_TYPE}" = "alpine" ]; then
        rc-service ddns stop >/dev/null 2>&1
        rc-update del ddns default >/dev/null 2>&1
        rm -f ${OPENRC_PATH}
    fi

    rm -f ${BIN_PATH}
    
    printf "${RED}是否要删除数据目录 ${WORK_DIR} (包含数据库)? [y/N]: ${NC}"
    read confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        rm -rf ${WORK_DIR}
        echo "${GREEN}已清理所有数据${NC}"
    else
        echo "${YELLOW}已保留数据目录: ${WORK_DIR}${NC}"
    fi
    
    echo "${GREEN}卸载完成。${NC}"
}

# 菜单界面
clear
echo "------------------------------------------"
echo "    DDNS Master 管理脚本"
echo "------------------------------------------"
echo " 1. 安装 DDNS"
echo " 2. 卸载 DDNS"
echo " 3. 重启服务"
echo " 4. 停止服务"
echo " 0. 退出"
echo "------------------------------------------"
printf "请输入选项: "
read opt

case "${opt}" in
    1) do_install ;;
    2) do_uninstall ;;
    3)
        detect_env
        if [ "$OS_TYPE" = "debian" ]; then systemctl restart ddns; else rc-service ddns restart; fi
        echo "${GREEN}服务已重启${NC}"
        ;;
    4)
        detect_env
        if [ "$OS_TYPE" = "debian" ]; then systemctl stop ddns; else rc-service ddns stop; fi
        echo "${YELLOW}服务已停止${NC}"
        ;;
    *) exit 0 ;;
esac
