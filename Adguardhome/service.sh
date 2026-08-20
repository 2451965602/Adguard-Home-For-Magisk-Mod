#!/system/bin/sh
MODDIR=${0%/*}
SCRIPT_DIR="/data/adb/agh/scripts"
ADGPATH="$MODDIR"
AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
MAIN_LOG="$AGH_DIR/agh.log"
MODULES_DIR="/data/adb/modules"
AGH_MODULE_PROP="$MODDIR/module.prop"

# 解锁脚本防篡改保护
find "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} \;

# 系统语言检测
locale=$(getprop persist.sys.locale)
[ -z "$locale" ] && locale="zh"
case $locale in zh*) lang=zh ;; *) lang=en ;; esac

# 检查hosts模块并中止启动
found_hosts=false
for module in "$MODULES_DIR"/*; do 
  [ -d "$module" ] && [ -f "$module/system/etc/hosts" ] && {
    found_hosts=true
    touch "$module/remove"
  }
done
if [ "$found_hosts" = true ]; then
    if [ "$lang" = "zh" ]; then
        MSG="检测到hosts模块，AdGuardHome启动已中止"
        DESC="⚠️ AdGuardHome已禁用 - 检测到hosts模块（已标记移除，请重启设备）"
    else
        MSG="Hosts module detected, AdGuardHome startup aborted"
        DESC="⚠️ AdGuardHome disabled - Hosts module detected (marked for removal, Please restart the device)"
    fi
    [ -f "$AGH_MODULE_PROP" ] && sed -i "s/description=.*/description=$DESC/" "$AGH_MODULE_PROP"
    echo "$(date '+%F %T') [ERROR] $MSG" >> "$MAIN_LOG"
    exit 1
fi

# 动态端口随机化
R1=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
R1=$((R1 % 35536 + 30000))
R2=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
R2=$((R2 % 35536 + 30000))
while [ "$R1" -eq "$R2" ]; do
    R2=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
    R2=$((R2 % 35536 + 30000))
done
YAML_TMP="$BIN_DIR/AdGuardHome.yaml.$$"
if awk -v dns_port="$R1" -v http_port="$R2" '
    /^[^[:space:]#][^:]*:/ { block="" }
    /^dns:[[:space:]]*$/ { block="dns" }
    /^http:[[:space:]]*$/ { block="http" }
    block == "dns" && /^  port:[[:space:]]*[0-9]+[[:space:]]*$/ {
        print "  port: " dns_port
        dns_found=1
        next
    }
    block == "http" && /^  address:[[:space:]]*127\.0\.0\.1:[0-9]+[[:space:]]*$/ {
        print "  address: 127.0.0.1:" http_port
        http_found=1
        next
    }
    { print }
    END { if (!dns_found || !http_found) exit 1 }
' "$BIN_DIR/AdGuardHome.yaml" > "$YAML_TMP" &&
    mv -f "$YAML_TMP" "$BIN_DIR/AdGuardHome.yaml"; then
    :
else
    rm -f "$YAML_TMP"
    echo "$(date '+%F %T') [ERROR] AdGuardHome.yaml 修改失败，已中止启动。" >> "$MAIN_LOG"
    exit 1
fi
if grep -q '^redir_port=' "$SCRIPT_DIR/config.prop" 2>/dev/null; then
    sed -i "s/^redir_port=.*/redir_port=$R1/" "$SCRIPT_DIR/config.prop" || {
        echo "$(date '+%F %T') [ERROR] config.prop 写入失败，已中止启动。" >> "$MAIN_LOG"
        exit 1
    }
else
    printf 'redir_port=%s\n' "$R1" >> "$SCRIPT_DIR/config.prop" || {
        echo "$(date '+%F %T') [ERROR] config.prop 写入失败，已中止启动。" >> "$MAIN_LOG"
        exit 1
    }
fi

if [ -f "$MAIN_LOG" ] && [ "$(wc -c < "$MAIN_LOG")" -gt 102400 ]; then
    : > "$MAIN_LOG"
fi

# 启动AdGuardHome
export SSL_CERT_DIR="/system/etc/security/cacerts/"
"$BIN_DIR/AdGuardHome" --no-check-update &

# 验证AdGuardHome是否启动成功
sleep 1
if pgrep -x "AdGuardHome" >/dev/null; then
    [ "$lang" = "zh" ] && echo "$(date '+%F %T') AdGuardHome 启动成功。" >> "$MAIN_LOG" || echo "$(date '+%F %T') AdGuardHome started successfully." >> "$MAIN_LOG"
else
    [ "$lang" = "zh" ] && echo "$(date '+%F %T') AdGuardHome启动失败，尝试重启..." >> "$MAIN_LOG" || echo "$(date '+%F %T') AdGuardHome failed to start, attempting restart..." >> "$MAIN_LOG"
    sleep 60
    exec "$0"
fi

# 启动模块附加脚本
"$SCRIPT_DIR/iptables.sh" &
"$SCRIPT_DIR/ModuleMOD.sh"
"$SCRIPT_DIR/NoAdsService.sh" &
"$SCRIPT_DIR/ProxyConfig.sh" &

# 执行脚本防篡改保护
find "$ADGPATH" -type f -name "*.sh" -exec chattr +i {} \;

# 日志超限时清空
[ "$(wc -c < "$MAIN_LOG")" -ge 102400 ] && : > "$MAIN_LOG"
