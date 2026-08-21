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

if [ -f "$MAIN_LOG" ] && [ "$(wc -c < "$MAIN_LOG")" -gt 102400 ]; then
    : > "$MAIN_LOG"
fi

# 健康检查：已有 AGH 在监听 yaml 中的端口，跳过重启（开机重复拉起场景）。
# 必须在端口随机化前检测——yaml 会被改写为新随机端口，运行中实例仍是旧端口。
# 不用 pgrep 判存活：开机早期 KernelSU 环境下 pgrep 可能不可用（返回 127 被
# 误判为进程不存在）。直接以端口监听为准，进程崩溃则端口不通。
agh_ok=0
cur_port=$(awk '/^dns:[[:space:]]*$/{f=1;next} f&&/^  port:[[:space:]]*[0-9]+/{print $2; exit}' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null)
if [ -n "$cur_port" ]; then
    hex_cur=$(printf '%04X' "$cur_port")
    if awk -v p="$hex_cur" '$2 ~ /^(0100007F|00000000):/ { split($2, a, ":"); if (toupper(a[2]) == p && $4 == "0A") { found=1; exit } } END { exit !found }' /proc/net/tcp 2>/dev/null &&
       awk -v p="$hex_cur" '$2 ~ /^(0100007F|00000000):/ { split($2, a, ":"); if (toupper(a[2]) == p && $3 ~ /:0000$/) { found=1; exit } } END { exit !found }' /proc/net/udp 2>/dev/null; then
        echo "$(date '+%F %T') AdGuardHome 已在运行（端口 $cur_port），跳过重启。" >> "$MAIN_LOG"
        agh_ok=1
    fi
fi

# 启动前的准备：端口随机化 + SQLite 锁清理
if [ "$agh_ok" = 0 ]; then
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
    # 清理强杀进程遗留的 SQLite 锁文件（sessions.db timeout 会导致 AGH fatal 退出）
    rm -f "$BIN_DIR/data/sessions.db-shm" "$BIN_DIR/data/sessions.db-wal" 2>/dev/null
    # 清理 AGH 异常退出遗留的 yaml 临时文件
    find "$BIN_DIR" -maxdepth 1 -name '.AdGuardHome.yaml*' -type f -exec rm -f {} \; 2>/dev/null
    # 启动AdGuardHome（stdout/stderr 记录到崩溃日志，用于诊断首轮启动失败）
    export SSL_CERT_DIR="/system/etc/security/cacerts/"
    : > "$AGH_DIR/agh_crash.log" 2>/dev/null
    "$BIN_DIR/AdGuardHome" --no-check-update >> "$AGH_DIR/agh_crash.log" 2>&1 &
    # 后台看护：crash log 超 512KB 时截断，防长期运行高频报错撑爆 /data 分区
    (
        while :; do
            sleep 300
            [ -f "$AGH_DIR/agh_crash.log" ] || continue
            if [ "$(wc -c < "$AGH_DIR/agh_crash.log")" -gt 524288 ]; then
                : > "$AGH_DIR/agh_crash.log"
            fi
        done
    ) &
fi

# 验证AdGuardHome是否启动成功（等待端口监听就绪，最多 10 秒）
# 不用 pgrep 判存活：开机早期 KernelSU 环境下 pgrep 可能不可用（返回 127 被
# 误判为进程不存在）。端口监听才是就绪的唯一判据；进程崩溃则端口不通，超时重试。
# shellcheck disable=SC2034  # try 仅作循环计数
for try in 1 2 3 4 5 6 7 8 9 10; do
    [ "$agh_ok" = 1 ] && break
    hex_port=$(printf '%04X' "$R1")
    # 检查 TCP 监听（状态 0A = LISTEN）
    tcp_ok=$(awk -v p="$hex_port" '
        $2 ~ /^(0100007F|00000000):/ {
            split($2, a, ":")
            if (toupper(a[2]) == p && $4 == "0A") { found=1; exit }
        }
        END { exit !found }
    ' /proc/net/tcp 2>/dev/null && echo yes || echo no)

    # 检查 UDP 监听（远程端口为 0）
    udp_ok=$(awk -v p="$hex_port" '
        $2 ~ /^(0100007F|00000000):/ {
            split($2, a, ":")
            if (toupper(a[2]) == p && $3 ~ /:0000$/) { found=1; exit }
        }
        END { exit !found }
    ' /proc/net/udp 2>/dev/null && echo yes || echo no)

    if [ "$tcp_ok" = "yes" ] && [ "$udp_ok" = "yes" ]; then
        agh_ok=1
        break
    fi
    echo "$(date '+%F %T') AdGuardHome端口测试失败，等待端口监听就绪..." >> "$MAIN_LOG"
    sleep 1
done

if [ "$agh_ok" = 1 ]; then
    [ "$lang" = "zh" ] && echo "$(date '+%F %T') AdGuardHome 启动成功。" >> "$MAIN_LOG" || echo "$(date '+%F %T') AdGuardHome started successfully." >> "$MAIN_LOG"
else
    [ "$lang" = "zh" ] && echo "$(date '+%F %T') AdGuardHome启动失败，尝试重启..." >> "$MAIN_LOG" || echo "$(date '+%F %T') AdGuardHome failed to start, attempting restart..." >> "$MAIN_LOG"
    # 重试前清理残留 AGH 进程及锁文件（exec "$0" 重新启动 service.sh）
    # 不依赖 pgrep/pkill 判余额：开机早期 KernelSU 环境下它们可能不可用。
    # 改用 killall（依二进制名），即便失败也无碍——端口已被随机化为新值，旧实例
    # 监听旧端口，重启后新实例拿新端口互不冲突；若 killall 成功则释放旧端口。
    killall -9 "AdGuardHome" 2>/dev/null
    # 等端口彻底释放（kill 异步生效）
    sleep 2
    killall -9 "AdGuardHome" 2>/dev/null
    rm -f "$BIN_DIR/data/sessions.db-shm" "$BIN_DIR/data/sessions.db-wal" 2>/dev/null
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
