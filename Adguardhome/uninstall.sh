#!/system/bin/sh
AGH_DIR="/data/adb/agh"
ADGPATH="/data/adb/modules/AdGuardHome"
PROXY_SCRIPT="$AGH_DIR/scripts/ProxyConfig.sh"

# 优雅停止本模块守护脚本和 AdGuardHome。
pkill -TERM -f '[/]iptables.sh'
wait_seconds=0
while pgrep -f '[/]iptables.sh' >/dev/null 2>&1; do
    [ "$wait_seconds" -ge 5 ] && break
    sleep 1
    wait_seconds=$((wait_seconds + 1))
done
if pgrep -f '[/]iptables.sh' >/dev/null 2>&1; then
    pkill -KILL -f '[/]iptables.sh'
fi

# 停止 AdGuardHome：TERM 后等待最多 5 秒，必要时 KILL 并确认退出。
pkill -TERM -x "AdGuardHome"
agh_process_stopped() {
    ! pgrep -x "AdGuardHome" >/dev/null 2>&1
}
wait_seconds=0
while ! agh_process_stopped; do
    [ "$wait_seconds" -ge 5 ] && break
    sleep 1
    wait_seconds=$((wait_seconds + 1))
done
if ! agh_process_stopped; then
    pkill -KILL -x "AdGuardHome"
fi
if ! agh_process_stopped; then
    printf '%s [ERROR] AdGuardHome 未退出，已中止卸载，未清理规则或目录。\n' \
        "$(date '+%F %T')" >> "$AGH_DIR/agh.log"
    exit 1
fi

# 只删除本模块自有链及其 OUTPUT 跳转。
# 旧版遗留的 ADGUARD/ADGUARD6 及直接 IPv6 DROP 规则所有权不明，故不处理。
while iptables -w 2 -t nat -D OUTPUT -j AGHMOD_DNS4 >/dev/null 2>&1; do :; done
iptables -w 2 -t nat -F AGHMOD_DNS4 >/dev/null 2>&1
iptables -w 2 -t nat -X AGHMOD_DNS4 >/dev/null 2>&1
while ip6tables -w 2 -D OUTPUT -j AGHMOD_DNS6 >/dev/null 2>&1; do :; done
ip6tables -w 2 -F AGHMOD_DNS6 >/dev/null 2>&1
ip6tables -w 2 -X AGHMOD_DNS6 >/dev/null 2>&1

# 停止 NoAdsService 和 ProxyConfig：TERM 后等待确认，必要时 KILL。
stop_module_process() {
    pkill -TERM -f "$1" 2>/dev/null
    w=0
    while pgrep -f "$1" >/dev/null 2>&1; do
        [ "$w" -ge 3 ] && break
        sleep 1
        w=$((w + 1))
    done
    pgrep -f "$1" >/dev/null 2>&1 && pkill -KILL -f "$1" 2>/dev/null
}
stop_module_process '[/]NoAdsService.sh'
stop_module_process '[/]ProxyConfig.sh'

# 还原代理模块修改
[ -f "$PROXY_SCRIPT" ] && "$PROXY_SCRIPT" --clean

# 解除锁定并删除残留文件
grep 'block_ad' "$AGH_DIR/scripts/NoAdsService.sh"|grep -o '".*"'|tr -d '"'|while IFS= read -r p;do [ -n "$p" ]&&[ -e "$p" ]&&find "$p" \( -type f -o -type d \) |while IFS= read -r f;do if [ -d "$f" ];then lsattr -d "$f"|grep -q "i-"&&{ chattr -i "$f";rmdir "$f";};else lsattr "$f"|grep -q "i-"&&{ chattr -i "$f";rm -f "$f";};fi;done;done

# 解除脚本防篡改保护
find "$AGH_DIR/scripts" "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} \;

# 删除AGH残留目录
[ -d "$AGH_DIR" ] && rm -rf "$AGH_DIR"
[ -d "$ADGPATH" ] && rm -rf "$ADGPATH"
