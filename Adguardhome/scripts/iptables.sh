#!/system/bin/sh
AGH_DIR="/data/adb/agh"
# shellcheck disable=SC1091
. "$AGH_DIR/scripts/config.prop"
MAIN_LOG="$AGH_DIR/agh.log"

# 仅由 service.sh 后台化；本脚本必须保持前台运行。
# 防止重复启动（不使用锁文件，避免把锁 FD 传给 AdGuardHome）。
case "$0" in
    */iptables.sh) [ "$(pgrep -f '[/]iptables.sh' | wc -l)" -gt 1 ] && exit ;;
esac

# shellcheck disable=SC2154
ensure_ipv4_rules() {
    iptables -w 2 -t nat -L AGHMOD_DNS4 >/dev/null 2>&1 || \
        iptables -w 2 -t nat -N AGHMOD_DNS4 || return 1

    # 该链是本模块专有链：刷新后重新写入完整规则集。
    iptables -w 2 -t nat -F AGHMOD_DNS4 || return 1
    while iptables -w 2 -t nat -D OUTPUT -j AGHMOD_DNS4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t nat -I OUTPUT -j AGHMOD_DNS4 || return 1
    iptables -w 2 -t nat -A AGHMOD_DNS4 -m owner --uid-owner root \
        -j RETURN || return 1
    iptables -w 2 -t nat -A AGHMOD_DNS4 -p udp --dport 53 -j REDIRECT \
        --to-ports "$redir_port" || return 1
    iptables -w 2 -t nat -A AGHMOD_DNS4 -p tcp --dport 53 -j REDIRECT \
        --to-ports "$redir_port" || return 1
}

ensure_ipv6_rules() {
    ip6tables -w 2 -L AGHMOD_DNS6 >/dev/null 2>&1 || \
        ip6tables -w 2 -N AGHMOD_DNS6 || return 1
    ip6tables -w 2 -F AGHMOD_DNS6 || return 1
    while ip6tables -w 2 -D OUTPUT -j AGHMOD_DNS6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -I OUTPUT -j AGHMOD_DNS6 || return 1
    ip6tables -w 2 -A AGHMOD_DNS6 -p udp --dport 53 -j DROP || return 1
    ip6tables -w 2 -A AGHMOD_DNS6 -p tcp --dport 53 -j DROP || return 1
}

rules4_are_valid() {
    iptables -w 2 -t nat -L AGHMOD_DNS4 >/dev/null 2>&1 && \
    iptables -w 2 -t nat -C OUTPUT -j AGHMOD_DNS4 >/dev/null 2>&1 && \
    iptables -w 2 -t nat -C AGHMOD_DNS4 -m owner --uid-owner root \
        -j RETURN >/dev/null 2>&1 && \
    iptables -w 2 -t nat -C AGHMOD_DNS4 -p udp --dport 53 -j REDIRECT \
        --to-ports "$redir_port" >/dev/null 2>&1 && \
    iptables -w 2 -t nat -C AGHMOD_DNS4 -p tcp --dport 53 -j REDIRECT \
        --to-ports "$redir_port" >/dev/null 2>&1
}

rules6_are_valid() {
    ip6tables -w 2 -L AGHMOD_DNS6 >/dev/null 2>&1 && \
    ip6tables -w 2 -C OUTPUT -j AGHMOD_DNS6 >/dev/null 2>&1 && \
    ip6tables -w 2 -C AGHMOD_DNS6 -p udp --dport 53 -j DROP >/dev/null 2>&1 && \
    ip6tables -w 2 -C AGHMOD_DNS6 -p tcp --dport 53 -j DROP >/dev/null 2>&1
}

# 检测 box 是否在指定表/链中接管了 DNS（UDP/TCP 53）。
# $1=iptables 二进制  $2=表  $3=链名
# 返回三态：0=active（box 接管），1=inactive（box 未接管），2=unknown（检测失败）。
# 用 -S OUTPUT | grep 捕获带条件的跳转（如 -p udp -j chain）。
# 链内规则用管道确认同一行同时含 --dport 53 和 -j REDIRECT|MARK|TPROXY。
box_chain_dns_active() {
    ipt_cmd=$1
    table=$2
    chain=$3
    # OUTPUT 是否跳转到该链（含带条件跳转，-C 无法匹配此类规则）。
    out_rules=$("$ipt_cmd" -w 2 -t "$table" -S OUTPUT 2>/dev/null)
    out_rc=$?
    [ $out_rc -ne 0 ] && return 2
    echo "$out_rules" | grep -qE -- "-j[[:space:]]+${chain}([[:space:]]|$)" || return 1
    # 链内是否存在 53 端口的 DNS 接管规则（同一行须同时含两个条件）。
    chain_rules=$("$ipt_cmd" -w 2 -t "$table" -S "$chain" 2>/dev/null)
    chain_rc=$?
    [ $chain_rc -ne 0 ] && return 2
    echo "$chain_rules" | grep -E -- "--dport[[:space:]]+53([[:space:]]|$)" | \
        grep -qE -- "-j[[:space:]]+(REDIRECT|MARK|TPROXY)([[:space:]]|$)" && return 0
    return 1
}

# IPv4 box DNS 接管检测（三态聚合：active 优先于 unknown）
box_dns4_active() {
    saw_unknown=0
    box_chain_dns_active iptables nat NAT_DNS_HIJACK; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    box_chain_dns_active iptables nat NAT_DNS_FORWARD; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    box_chain_dns_active iptables mangle BOX_LOCAL; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    [ $saw_unknown -eq 1 ] && return 2
    return 1
}

# IPv6 box DNS 接管检测（三态聚合：active 优先于 unknown）
box_dns6_active() {
    saw_unknown=0
    box_chain_dns_active ip6tables nat NAT_DNS_HIJACK; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    box_chain_dns_active ip6tables nat NAT_DNS_FORWARD; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    box_chain_dns_active ip6tables mangle BOX_LOCAL; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    [ $saw_unknown -eq 1 ] && return 2
    return 1
}

# 清理 AGH IPv4 DNS 劫持链（幂等）。
cleanup_agh4_rules() {
    while iptables -w 2 -t nat -D OUTPUT -j AGHMOD_DNS4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t nat -F AGHMOD_DNS4 >/dev/null 2>&1
    iptables -w 2 -t nat -X AGHMOD_DNS4 >/dev/null 2>&1
}

# 清理 AGH IPv6 DNS 劫持链（幂等）。
cleanup_agh6_rules() {
    while ip6tables -w 2 -D OUTPUT -j AGHMOD_DNS6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -F AGHMOD_DNS6 >/dev/null 2>&1
    ip6tables -w 2 -X AGHMOD_DNS6 >/dev/null 2>&1
}

# 启动 AdGuardHome（掉进程重启）
restart_agh() {
    pgrep -x "AdGuardHome" || {
        {
            case "$(getprop persist.sys.locale)" in
                zh*) echo "$(date '+%F %T') AdGuardHome 进程丢失，正在重启..." ;;
                *)   echo "$(date '+%F %T') AdGuardHome process lost, restarting..." ;;
            esac
        } >> "$MAIN_LOG"
        export SSL_CERT_DIR="/system/etc/security/cacerts/"
        "$AGH_DIR/bin/AdGuardHome" --no-check-update &
    }
}

# 规则守护循环
while true; do
    restart_agh
    # IPv4 和 IPv6 独立检测：box 可能只接管其中一栈。
    # 三态：0=active（清理 AGH），1=inactive（安装/维护 AGH），2=unknown（跳过本轮）。
    box_dns4_active; v4_rc=$?
    case $v4_rc in
        0) cleanup_agh4_rules ;;
        1) rules4_are_valid || { ensure_ipv4_rules || :; } ;;
    esac
    box_dns6_active; v6_rc=$?
    case $v6_rc in
        0) cleanup_agh6_rules ;;
        1) rules6_are_valid || { ensure_ipv6_rules || :; } ;;
    esac
    sleep 60
done
