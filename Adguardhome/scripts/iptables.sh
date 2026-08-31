#!/system/bin/sh
AGH_DIR="/data/adb/agh"
# shellcheck disable=SC1091
. "$AGH_DIR/scripts/config.prop"
MAIN_LOG="$AGH_DIR/agh.log"
# 端口真相源：AGH 实际加载的 AdGuardHome.yaml 中 dns.port。
# config.prop 可能因 service.sh 重试循环漂移，yaml 才是运行实例的真实端口；
# 重定向到漂移端口会导致全系统 DNS 中断。
AGH_YAML_PORT=$(awk '/^dns:[[:space:]]*$/{f=1;next} f&&/^  port:[[:space:]]*[0-9]+/{print $2; exit}' "$AGH_DIR/bin/AdGuardHome.yaml" 2>/dev/null)
[ -n "$AGH_YAML_PORT" ] && redir_port="$AGH_YAML_PORT"

# 仅由 service.sh 后台化；本脚本必须保持前台运行。
# 防止重复启动：mkdir 原子锁（不使用锁文件，避免把锁 FD 传给 AdGuardHome；
# 也不依赖 pgrep -f——它会误计命令替换 fork 的子进程，且开机早期可能不可用）。
LOCK_DIR="/data/adb/agh/.iptables.lock"
if [ -d "$LOCK_DIR" ]; then
    # PID 存活检测：检查锁持有者是否还活着（SIGKILL 不触发 trap 时的兜底）。
    # 比纯时间超时更精准：持有者一死就立即清锁，不用等 2 小时。
    lock_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    lock_alive=0
    case "$lock_pid" in
        ''|*[!0-9]*)
            # 无效 PID（旧版锁或损坏）→ 落入时间超时检查
            ;;
        *)
            # 检查 PID 对应的进程是否存活且确实是 iptables.sh
            lock_cmd=$(tr '\000' ' ' < "/proc/${lock_pid}/cmdline" 2>/dev/null)
            case "$lock_cmd" in *iptables.sh*) lock_alive=1 ;; esac
            ;;
    esac
    if [ "$lock_alive" -eq 1 ]; then
        # 持有者还活着 → 本实例退出
        exit
    fi
    # 持有者已死或 PID 无效 → 清理残留锁
    rm -rf "$LOCK_DIR"
fi
mkdir "$LOCK_DIR" 2>/dev/null || exit
printf '%s\n' "$$" > "$LOCK_DIR/pid"
trap 'rm -f "$LOCK_DIR/pid" 2>/dev/null; rmdir "$LOCK_DIR" 2>/dev/null' EXIT

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

# ===== DoT(853) 阻断链（filter 表）=====
# 目的：阻断普通应用的 DoT 流量，防止 DNS 绕过 AGH（吸收自上游 20260829）。
# 与上游的差异：带 root 豁免（--uid-owner root RETURN）——mihomo/AGH 等代理与
# DNS 内核均以 root 运行且需要 DoT 能力；配套 box 规则约定"仅禁止非 mihomo
# 访问 DoT"，filter OUTPUT 维度与之对齐（PROCESS-NAME 粒度由 box 侧实现）。
ensure_dot4_rules() {
    iptables -w 2 -t filter -L AGHMOD_DOT4 >/dev/null 2>&1 || \
        iptables -w 2 -t filter -N AGHMOD_DOT4 || return 1
    iptables -w 2 -t filter -F AGHMOD_DOT4 || return 1
    while iptables -w 2 -t filter -D OUTPUT -j AGHMOD_DOT4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t filter -I OUTPUT -j AGHMOD_DOT4 || return 1
    iptables -w 2 -t filter -A AGHMOD_DOT4 -m owner --uid-owner root \
        -j RETURN || return 1
    iptables -w 2 -t filter -A AGHMOD_DOT4 -p tcp --dport 853 -j DROP || return 1
    iptables -w 2 -t filter -A AGHMOD_DOT4 -p udp --dport 853 -j DROP || return 1
}

ensure_dot6_rules() {
    ip6tables -w 2 -t filter -L AGHMOD_DOT6 >/dev/null 2>&1 || \
        ip6tables -w 2 -t filter -N AGHMOD_DOT6 || return 1
    ip6tables -w 2 -t filter -F AGHMOD_DOT6 || return 1
    while ip6tables -w 2 -t filter -D OUTPUT -j AGHMOD_DOT6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -t filter -I OUTPUT -j AGHMOD_DOT6 || return 1
    ip6tables -w 2 -t filter -A AGHMOD_DOT6 -m owner --uid-owner root \
        -j RETURN || return 1
    ip6tables -w 2 -t filter -A AGHMOD_DOT6 -p tcp --dport 853 -j DROP || return 1
    ip6tables -w 2 -t filter -A AGHMOD_DOT6 -p udp --dport 853 -j DROP || return 1
}

dot4_rules_valid() {
    iptables -w 2 -t filter -L AGHMOD_DOT4 >/dev/null 2>&1 && \
    iptables -w 2 -t filter -C OUTPUT -j AGHMOD_DOT4 >/dev/null 2>&1 && \
    iptables -w 2 -t filter -C AGHMOD_DOT4 -m owner --uid-owner root \
        -j RETURN >/dev/null 2>&1 && \
    iptables -w 2 -t filter -C AGHMOD_DOT4 -p tcp --dport 853 -j DROP >/dev/null 2>&1 && \
    iptables -w 2 -t filter -C AGHMOD_DOT4 -p udp --dport 853 -j DROP >/dev/null 2>&1
}

dot6_rules_valid() {
    ip6tables -w 2 -t filter -L AGHMOD_DOT6 >/dev/null 2>&1 && \
    ip6tables -w 2 -t filter -C OUTPUT -j AGHMOD_DOT6 >/dev/null 2>&1 && \
    ip6tables -w 2 -t filter -C AGHMOD_DOT6 -m owner --uid-owner root \
        -j RETURN >/dev/null 2>&1 && \
    ip6tables -w 2 -t filter -C AGHMOD_DOT6 -p tcp --dport 853 -j DROP >/dev/null 2>&1 && \
    ip6tables -w 2 -t filter -C AGHMOD_DOT6 -p udp --dport 853 -j DROP >/dev/null 2>&1
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
# box 的 IPv6 nat 链带 6 后缀（NAT_DNS_HIJACK6/NAT_DNS_FORWARD6），与 IPv4 链名不同。
# tun 模式下 box 不创建任何 DNS 劫持链（DNS 由 tun 接口内部劫持），三链探测必然
# miss，此时 AGH 抢挂 nat REDIRECT 是预期接管行为：本机 DNS 进 AGH 而非 mihomo。
box_dns6_active() {
    saw_unknown=0
    box_chain_dns_active ip6tables nat NAT_DNS_HIJACK6; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    box_chain_dns_active ip6tables nat NAT_DNS_FORWARD6; rc=$?
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

# 清理 DoT(853) 阻断链（幂等）。与 DNS 劫持链不同：DoT 阻断不与 box 冲突
# （box 不创建 filter 表 OUTPUT 的 853 规则），box 接管期间仍保持生效。
cleanup_dot4_rules() {
    while iptables -w 2 -t filter -D OUTPUT -j AGHMOD_DOT4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t filter -F AGHMOD_DOT4 >/dev/null 2>&1
    iptables -w 2 -t filter -X AGHMOD_DOT4 >/dev/null 2>&1
}

cleanup_dot6_rules() {
    while ip6tables -w 2 -t filter -D OUTPUT -j AGHMOD_DOT6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -t filter -F AGHMOD_DOT6 >/dev/null 2>&1
    ip6tables -w 2 -t filter -X AGHMOD_DOT6 >/dev/null 2>&1
}

# AGH 进程健康检查：仅记日志警告，不拉起（生命周期由 service.sh 管理）。
# 不用 pgrep 判存活：开机早期 KernelSU 环境下 pgrep 可能不可用（返回 127 被
# 误判为进程不存在），导致每 60 秒刷一条误报警告。以 redir_port 端口监听为准。
warn_if_agh_down() {
    hex_port=$(printf '%04X' "$redir_port" 2>/dev/null)
    [ -n "$hex_port" ] || return
    awk -v p="$hex_port" '$2 ~ /^(0100007F|00000000):/ { split($2, a, ":"); if (toupper(a[2]) == p && $4 == "0A") { found=1; exit } } END { exit !found }' /proc/net/tcp 2>/dev/null && return
    awk -v p="$hex_port" '$2 ~ /^(0100007F|00000000):/ { split($2, a, ":"); if (toupper(a[2]) == p && $3 ~ /:0000$/) { found=1; exit } } END { exit !found }' /proc/net/udp 2>/dev/null && return
    case "$(getprop persist.sys.locale)" in
        zh*) echo "$(date '+%F %T') [WARN] AdGuardHome 端口 $redir_port 未监听，等待 service.sh 拉起" ;;
        *)   echo "$(date '+%F %T') [WARN] AdGuardHome port $redir_port not listening, awaiting service.sh restart" ;;
    esac >> "$MAIN_LOG"
}

# 规则守护循环
while true; do
    # 每轮重读 yaml 端口真相源（吸收自上游"每轮重读配置"的思想）：
    # service.sh 重试循环会随机化新端口并重启 AGH，本守护进程因锁持续存活，
    # 内存中的 redir_port 会过期——不重读就会把 DNS 重定向到死端口。
    AGH_YAML_PORT=$(awk '/^dns:[[:space:]]*$/{f=1;next} f&&/^  port:[[:space:]]*[0-9]+/{print $2; exit}' "$AGH_DIR/bin/AdGuardHome.yaml" 2>/dev/null)
    [ -n "$AGH_YAML_PORT" ] && redir_port="$AGH_YAML_PORT"
    warn_if_agh_down
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
    # DoT(853) 阻断独立维护：不依赖 box 接管状态，规则缺失即补齐。
    dot4_rules_valid || { ensure_dot4_rules || :; }
    dot6_rules_valid || { ensure_dot6_rules || :; }
    sleep 60
done
