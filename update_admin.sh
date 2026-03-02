#!/bin/bash

# 自动获取当前项目路径
REALM_PATH=$(pwd)
SERVICE_FILE="/etc/systemd/system/realm.service"

# 1. 获取当前 SSH 登录的 IP
# 兼容多种环境提取 IP
CURRENT_IP=$(who -m | awk '{print $NF}' | tr -d '()')
if [ -z "$CURRENT_IP" ]; then
    # 备选方案：通过 ss 命令（netstat 的现代替代品）抓取 ESTABLISHED 状态的 ssh 来源
    CURRENT_IP=$(ss -tnp | grep ':22' | grep 'ESTAB' | awk '{print $5}' | cut -d] -f1 | tr -d '[' | cut -d: -f1 | head -n 1)
fi

# 如果还是没抓到，直接退出（比如你还没登录 SSH，或者在本地直接运行）
if [ -z "$CURRENT_IP" ] || [[ "$CURRENT_IP" == *"/"* ]]; then
    exit 0
fi

# 2. 检查当前 service 文件中的白名单
if [ ! -f "$SERVICE_FILE" ]; then
    echo "错误: $SERVICE_FILE 不存在"
    exit 1
fi
OLD_IP=$(grep -oP '(?<=-admin )\d+\.\d+\.\d+\.\d+' $SERVICE_FILE)

# 3. 如果 IP 变了，执行平滑更新
if [ "$CURRENT_IP" != "$OLD_IP" ]; then
    echo "[$(date)] 检测到 IP 变更: $OLD_IP -> $CURRENT_IP" >> "$REALM_PATH/whitelist_update.log"
    sudo sed -i "s/-admin $OLD_IP/-admin $CURRENT_IP/g" $SERVICE_FILE
    sudo systemctl daemon-reload
    sudo systemctl restart realm
fi
