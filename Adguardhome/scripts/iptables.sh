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
# 用 -S 检查 OUTPUT/PREROUTING 中的跳转（如 -p udp -j chain）。
# 链内规则用管道确认同一行同时含 --dport 53 和 DNS 接管 target。
box_chain_dns_active() {
    ipt_cmd=$1
    table=$2
    chain=$3
    chain_seen=0
    for hook in OUTPUT PREROUTING; do
        # -C 无法匹配带条件跳转，使用 -S 保留完整规则文本。
        hook_rules=$("$ipt_cmd" -w 2 -t "$table" -S "$hook" 2>/dev/null)
        hook_rc=$?
        [ $hook_rc -ne 0 ] && return 2
        echo "$hook_rules" | grep -qE -- "-j[[:space:]]+${chain}([[:space:]]|$)" || continue
        chain_seen=1
        # 链内规则须同时含 53 端口和 DNS 接管 target。
        chain_rules=$("$ipt_cmd" -w 2 -t "$table" -S "$chain" 2>/dev/null)
        chain_rc=$?
        [ $chain_rc -ne 0 ] && return 2
        echo "$chain_rules" | grep -E -- "--dport[[:space:]]+53([[:space:]]|$)" | \
            grep -qE -- "-j[[:space:]]+(REDIRECT|DNAT|MARK|TPROXY)([[:space:]]|$)" && return 0
    done
    [ $chain_seen -eq 0 ] || return 1
    return 1
}

# TUN 模式可能直接在 mangle hook 上对 DNS 使用 TPROXY，而不经过 BOX_LOCAL。
# 同样返回 active/inactive/unknown 三态；两个 hook 任一失败都不擅自改动 AGH 规则。
box_tun_dns_active() {
    ipt_cmd=$1
    saw_rule=0
    for hook in OUTPUT PREROUTING; do
        mangle_rules=$("$ipt_cmd" -w 2 -t mangle -S "$hook" 2>/dev/null)
        mangle_rc=$?
        [ $mangle_rc -ne 0 ] && return 2
        echo "$mangle_rules" | grep -E -- "--dport[[:space:]]+53([[:space:]]|$)" | \
            grep -qE -- "-j[[:space:]]+TPROXY([[:space:]]|$)" && saw_rule=1
    done
    [ $saw_rule -eq 1 ] && return 0
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
    box_tun_dns_active iptables; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    [ $saw_unknown -eq 1 ] && return 2
    return 1
}

# IPv6 box DNS 接管检测（三态聚合：active 优先于 unknown）
# box 的 IPv6 nat 链带 6 后缀（NAT_DNS_HIJACK6/NAT_DNS_FORWARD6），与 IPv4 链名不同。
# tun 模式下 box 不创建任何 DNS 劫持链（DNS 由 tun 接口内部劫持），三链探测必然
# miss，此时 AGH 抢挂 nat REDIRECT 是预期接管行为：本机 DNS 进 AGH 而非 mihomo。
ipv6_nat_is_supported() {
    # /proc/net/ip6_tables_names is scoped to the current network namespace and
    # lists the IPv6 tables actually registered in this module context.
    if [ -r /proc/net/ip6_tables_names ]; then
        grep -qx 'nat' /proc/net/ip6_tables_names
        return $?
    fi
    # Older kernels may not expose the proc entry; fall back to a quiet table
    # listing rather than probing individual chains and misclassifying errors.
    ip6tables -w 2 -t nat -L >/dev/null 2>&1
}

box_dns6_active() {
    saw_unknown=0
    IPV6_NAT_UNSUPPORTED=0
    if ipv6_nat_is_supported; then
        # 不同 Box 版本对 IPv6 链名有无 6 后缀两种实现，均保守识别。
        box_chain_dns_active ip6tables nat NAT_DNS_HIJACK; rc=$?
        [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
        box_chain_dns_active ip6tables nat NAT_DNS_FORWARD; rc=$?
        [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
        box_chain_dns_active ip6tables nat NAT_DNS_HIJACK6; rc=$?
        [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
        box_chain_dns_active ip6tables nat NAT_DNS_FORWARD6; rc=$?
        [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    else
        IPV6_NAT_UNSUPPORTED=1
    fi
    box_chain_dns_active ip6tables mangle BOX_LOCAL; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    box_tun_dns_active ip6tables; rc=$?
    [ $rc -eq 0 ] && return 0; [ $rc -eq 2 ] && saw_unknown=1
    [ $saw_unknown -eq 1 ] && return 2
    [ "$IPV6_NAT_UNSUPPORTED" -eq 1 ] && return 3
    return 1
}

log_box_dns_unknown() {
    box_family=$1
    echo "$(date '+%F %T') [WARN] Box IPv${box_family} DNS takeover detection unknown; skip AGH DNS rule changes" >> "$MAIN_LOG"
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

# ===== SNI 过滤链（filter 表）=====
# 这是 custom core 的专用入口，不触碰 BOX_*、DNS 或其他通用 filter 链。
# 规则只将应用 UID 范围内、连接原始方向前 20,000 字节的 TCP 流量送入
# custom core 的 NFQUEUE；--queue-bypass 保证队列进程异常时不阻断网络。
# SNI 默认关闭：仅当 yaml 的 sni_filter.enabled=true，或
# filtering.blocking_mode=strong 时安装。配置无效时清理两个专用链；某一
# 地址族的能力缺失或规则失败时只清理该族，避免影响另一族的正常过滤。
cleanup_sni4_rules() {
    while iptables -w 2 -t filter -D OUTPUT -j AGHMOD_SNI4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t filter -F AGHMOD_SNI4 >/dev/null 2>&1
    iptables -w 2 -t filter -X AGHMOD_SNI4 >/dev/null 2>&1
}

cleanup_sni6_rules() {
    while ip6tables -w 2 -t filter -D OUTPUT -j AGHMOD_SNI6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -t filter -F AGHMOD_SNI6 >/dev/null 2>&1
    ip6tables -w 2 -t filter -X AGHMOD_SNI6 >/dev/null 2>&1
}

cleanup_sni_rules() {
    cleanup_sni4_rules
    cleanup_sni6_rules
}

# QUIC/DoQ 使用独立的 UDP 链，绝不改变现有 TCP SNI 链。仅观察每条
# conntrack 流的前 16KiB，并通过相同的 NFQUEUE 交给 custom core。
cleanup_quic4_rules() {
    while iptables -w 2 -t filter -D OUTPUT -j AGHMOD_QUIC4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t filter -F AGHMOD_QUIC4 >/dev/null 2>&1
    iptables -w 2 -t filter -X AGHMOD_QUIC4 >/dev/null 2>&1
}

cleanup_quic6_rules() {
    while ip6tables -w 2 -t filter -D OUTPUT -j AGHMOD_QUIC6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -t filter -F AGHMOD_QUIC6 >/dev/null 2>&1
    ip6tables -w 2 -t filter -X AGHMOD_QUIC6 >/dev/null 2>&1
}

cleanup_quic_rules() {
    cleanup_quic4_rules
    cleanup_quic6_rules
}

# 读取顶层 YAML 标量。只认顶层段名和两个空格缩进，避免误读用户规则。
sni_yaml_value() {
    sni_yaml_section=$1
    sni_yaml_key=$2
    awk -v section="$sni_yaml_section" -v key="$sni_yaml_key" '
        $0 == section ":" { in_section=1; next }
        /^[^[:space:]#][^:]*:/ { in_section=0 }
        in_section && $0 ~ "^  " key ":[[:space:]]*" {
            sub("^  " key ":[[:space:]]*", "")
            sub("[[:space:]]*#.*$", "")
            print
            exit
        }
    ' "$AGH_DIR/bin/AdGuardHome.yaml" 2>/dev/null | tr -d "'\"\r"
}

# Extract only simple block lists under sni_filter. YAML features outside this
# deliberately narrow grammar fail closed instead of being partially interpreted.
sni_yaml_list() {
    awk -v wanted="$1" '
        function fail() { invalid=1 }
        /^[[:space:]]*($|#)/ { next }
        $0 == "sni_filter:" {
            sections++
            if (sections > 1) fail()
            in_section=1
            next
        }
        /^[^[:space:]#][^:]*:/ {
            in_section=0
            in_list=0
        }
        !in_section { next }
        /^  [A-Za-z_][A-Za-z0-9_-]*:/ {
            property=$0
            sub(/^  /, "", property)
            sub(/:.*/, "", property)
            in_list=0
            if (property == wanted) {
                found++
                if (found > 1) fail()
                if (wanted == "uids" && $0 == "  uids: []") {
                    empty_list=1
                    in_list=0
                    next
                }
                if ($0 != "  " wanted ":") fail()
                in_list=1
            }
            next
        }
        in_list {
            if ($0 !~ /^    - /) {
                fail()
                next
            }
            value=substr($0, 7)
            if (wanted == "uids") {
                # AGH may serialize the same scalar bare, single-quoted, or double-quoted.
                # Remove only YAML comments introduced by separating whitespace; then
                # unwrap one matching quote pair and require exactly decimal start-end.
                sub(/[[:space:]]+#.*$/, "", value)
                sub(/[[:space:]]*$/, "", value)
                uid_quote=substr(value, 1, 1)
                if (uid_quote == "\"" || uid_quote == sprintf("%c", 39)) {
                    if (length(value) < 3 || substr(value, length(value), 1) != uid_quote) {
                        fail()
                        next
                    }
                    value=substr(value, 2, length(value)-2)
                }
                if (value !~ /^[0-9]+-[0-9]+$/) {
                    fail()
                    next
                }
            } else {
                if (value !~ /^[0-9]+([[:space:]]+#.*)?[[:space:]]*$/) {
                    fail()
                    next
                }
                sub(/[[:space:]]+#.*$/, "", value)
                sub(/[[:space:]]*$/, "", value)
            }
            if (count++) result=result ","
            result=result value
        }
        END {
            if (sections != 1 || found != 1 || invalid || count == 0 &&
                (wanted != "uids" || empty_list != 1)) exit 1
            print result
        }
    ' "$AGH_DIR/bin/AdGuardHome.yaml" 2>/dev/null
}

load_sni_rule_lists() {
    sni_uid_range=$(sni_yaml_list uids)
    sni_uid_list_status=$?
    [ "$sni_uid_list_status" -eq 0 ] || sni_uid_range=
    sni_ports=$(sni_yaml_list ports) || sni_ports=
    sni_quic_ports=$(sni_yaml_list quic_ports) || sni_quic_ports=
}

# 返回：0=应安装，1=明确关闭，2=配置无效。
sni_filter_state() {
    sni_enabled=$(sni_yaml_value sni_filter enabled)
    sni_blocking_mode=$(sni_yaml_value filtering blocking_mode)
    sni_queue_num=$(sni_yaml_value sni_filter queue_num)

    case "$sni_enabled" in
        true|false) ;;
        *) return 2 ;;
    esac
    # 仅依赖 custom core 约定的 strong，其余非空模式都表示明确关闭；
    # 不在脚本中硬编码未来 core 可能新增的 blocking_mode。
    case "$sni_blocking_mode" in
        ''|*[!a-zA-Z0-9_-]*) return 2 ;;
    esac
    case "$sni_queue_num" in
        ''|*[!0-9]*) return 2 ;;
    esac
    [ "$sni_queue_num" -le 65535 ] || return 2

    # enabled=false 仍可由 strong 模式显式启用外部 SNI 规则。
    if [ "$sni_enabled" = true ] || [ "$sni_blocking_mode" = strong ]; then
        return 0
    fi
    return 1
}

sni_uid_ranges_are_valid() {
    # An explicitly empty UID list means every process; other values are ranges.
    [ "$sni_uid_list_status" -eq 0 ] || return 1
    [ -n "$sni_uid_range" ] || return 0
    case "$sni_uid_range" in
        *[!0-9,-]*|,*|*,|*,,*) return 1 ;;
    esac
    old_ifs=$IFS
    IFS=,
    sni_uid_range_count=0
    for sni_uid_segment in $sni_uid_range; do
        case "$sni_uid_segment" in *-*-*|*-) IFS=$old_ifs; return 1 ;; esac
        case "$sni_uid_segment" in *-*) ;; *) IFS=$old_ifs; return 1 ;; esac
        sni_uid_start=${sni_uid_segment%-*}
        sni_uid_end=${sni_uid_segment#*-}
        [ -n "$sni_uid_start" ] && [ -n "$sni_uid_end" ] || {
            IFS=$old_ifs
            return 1
        }
        # Strip leading zeros so decimal values such as 08 are not parsed as octal.
        sni_uid_start_cmp=$(printf '%s' "$sni_uid_start" | sed 's/^0*//')
        sni_uid_end_cmp=$(printf '%s' "$sni_uid_end" | sed 's/^0*//')
        [ -n "$sni_uid_start_cmp" ] || sni_uid_start_cmp=0
        [ -n "$sni_uid_end_cmp" ] || sni_uid_end_cmp=0
        [ "$sni_uid_start_cmp" -le "$sni_uid_end_cmp" ] 2>/dev/null || {
            IFS=$old_ifs
            return 1
        }
        sni_uid_range_count=$((sni_uid_range_count + 1))
    done
    IFS=$old_ifs
    [ "$sni_uid_range_count" -gt 0 ]
}

# Empty uid means no owner match (all processes). Keep rule construction and
# validity checks identical so existing rules are not needlessly rebuilt.
sni_tcp_rule() {
    sni_rule_cmd=$1
    sni_rule_op=$2
    sni_rule_chain=$3
    sni_rule_port=$4
    sni_rule_uid=$5
    if [ -n "$sni_rule_uid" ]; then
        "$sni_rule_cmd" -w 2 -t filter "$sni_rule_op" "$sni_rule_chain" \
            -p tcp --dport "$sni_rule_port" -m owner --uid-owner "$sni_rule_uid" \
            -m connbytes --connbytes 0:20000 --connbytes-dir original \
            --connbytes-mode bytes -j NFQUEUE --queue-num "$sni_queue_num" \
            --queue-bypass
    else
        "$sni_rule_cmd" -w 2 -t filter "$sni_rule_op" "$sni_rule_chain" \
            -p tcp --dport "$sni_rule_port" \
            -m connbytes --connbytes 0:20000 --connbytes-dir original \
            --connbytes-mode bytes -j NFQUEUE --queue-num "$sni_queue_num" \
            --queue-bypass
    fi
}

sni_quic_rule() {
    sni_rule_cmd=$1
    sni_rule_op=$2
    sni_rule_chain=$3
    sni_rule_port=$4
    sni_rule_uid=$5
    if [ -n "$sni_rule_uid" ]; then
        "$sni_rule_cmd" -w 2 -t filter "$sni_rule_op" "$sni_rule_chain" \
            -p udp --dport "$sni_rule_port" -m owner --uid-owner "$sni_rule_uid" \
            -m connbytes --connbytes 0:16383 --connbytes-dir original \
            --connbytes-mode bytes -m length --length 0:16384 \
            -j NFQUEUE --queue-num "$sni_queue_num" --queue-bypass
    else
        "$sni_rule_cmd" -w 2 -t filter "$sni_rule_op" "$sni_rule_chain" \
            -p udp --dport "$sni_rule_port" \
            -m connbytes --connbytes 0:16383 --connbytes-dir original \
            --connbytes-mode bytes -m length --length 0:16384 \
            -j NFQUEUE --queue-num "$sni_queue_num" --queue-bypass
    fi
}

sni_ports_are_valid() {
    sni_uid_ranges_are_valid || return 1

    old_ifs=$IFS
    IFS=,
    sni_port_count=0
    for sni_port in $sni_ports; do
        case "$sni_port" in
            ''|*[!0-9]*) IFS=$old_ifs; return 1 ;;
        esac
        [ "$sni_port" -ge 1 ] && [ "$sni_port" -le 65535 ] || {
            IFS=$old_ifs
            return 1
        }
        sni_port_count=$((sni_port_count + 1))
    done
    IFS=$old_ifs
    [ "$sni_port_count" -gt 0 ]
}

sni_quic_ports_are_valid() {
    [ -n "$sni_quic_ports" ] && sni_uid_ranges_are_valid || return 1

    case "$sni_quic_ports" in
        *[!0-9,]*|,*|*,|*,,*) return 1 ;;
    esac
    old_ifs=$IFS
    IFS=,
    sni_port_count=0
    for sni_port in $sni_quic_ports; do
        case "$sni_port" in ''|*[!0-9]*) IFS=$old_ifs; return 1 ;; esac
        [ "$sni_port" -ge 1 ] && [ "$sni_port" -le 65535 ] || {
            IFS=$old_ifs
            return 1
        }
        sni_port_count=$((sni_port_count + 1))
    done
    IFS=$old_ifs
    [ "$sni_port_count" -gt 0 ]
}

ensure_quic4_rules() {
    iptables -w 2 -t filter -L AGHMOD_QUIC4 >/dev/null 2>&1 || \
        iptables -w 2 -t filter -N AGHMOD_QUIC4 || return 1
    iptables -w 2 -t filter -F AGHMOD_QUIC4 || return 1
    while iptables -w 2 -t filter -D OUTPUT -j AGHMOD_QUIC4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t filter -I OUTPUT -j AGHMOD_QUIC4 || return 1
    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_quic_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_quic_rule iptables -A AGHMOD_QUIC4 "$sni_port" "$sni_uid_segment" || { IFS=$old_ifs; return 1; }
            done
        else
            sni_quic_rule iptables -A AGHMOD_QUIC4 "$sni_port" '' || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

ensure_quic6_rules() {
    ip6tables -w 2 -t filter -L AGHMOD_QUIC6 >/dev/null 2>&1 || \
        ip6tables -w 2 -t filter -N AGHMOD_QUIC6 || return 1
    ip6tables -w 2 -t filter -F AGHMOD_QUIC6 || return 1
    while ip6tables -w 2 -t filter -D OUTPUT -j AGHMOD_QUIC6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -t filter -I OUTPUT -j AGHMOD_QUIC6 || return 1
    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_quic_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_quic_rule ip6tables -A AGHMOD_QUIC6 "$sni_port" "$sni_uid_segment" || { IFS=$old_ifs; return 1; }
            done
        else
            sni_quic_rule ip6tables -A AGHMOD_QUIC6 "$sni_port" '' || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

quic4_rules_are_valid() {
    iptables -w 2 -t filter -L AGHMOD_QUIC4 >/dev/null 2>&1 || return 1
    iptables -w 2 -t filter -C OUTPUT -j AGHMOD_QUIC4 >/dev/null 2>&1 || return 1
    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_quic_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_quic_rule iptables -C AGHMOD_QUIC4 "$sni_port" "$sni_uid_segment" >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
            done
        else
            sni_quic_rule iptables -C AGHMOD_QUIC4 "$sni_port" '' >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

quic6_rules_are_valid() {
    ip6tables -w 2 -t filter -L AGHMOD_QUIC6 >/dev/null 2>&1 || return 1
    ip6tables -w 2 -t filter -C OUTPUT -j AGHMOD_QUIC6 >/dev/null 2>&1 || return 1
    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_quic_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_quic_rule ip6tables -C AGHMOD_QUIC6 "$sni_port" "$sni_uid_segment" >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
            done
        else
            sni_quic_rule ip6tables -C AGHMOD_QUIC6 "$sni_port" '' >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

SNI_QUIC_CONFIG_WARNED=0
maintain_quic_rules() {
    sni_inspect_quic=$(sni_yaml_value sni_filter inspect_quic)
    if [ -z "$sni_inspect_quic" ]; then
        cleanup_quic_rules
        if [ "$SNI_QUIC_CONFIG_WARNED" -eq 0 ]; then
            echo "$(date '+%F %T') [WARN] sni_filter.inspect_quic is missing; treating as false and removing QUIC NFQUEUE rules" >> "$MAIN_LOG"
            SNI_QUIC_CONFIG_WARNED=1
        fi
        return
    fi
    case "$sni_inspect_quic" in
        true|false) ;;
        *)
            cleanup_quic_rules
            if [ "$SNI_QUIC_CONFIG_WARNED" -eq 0 ]; then
                echo "$(date '+%F %T') [WARN] Invalid sni_filter.inspect_quic; treating as false and removing QUIC NFQUEUE rules" >> "$MAIN_LOG"
                SNI_QUIC_CONFIG_WARNED=1
            fi
            return
            ;;
    esac
    if ! sni_quic_ports_are_valid; then
        cleanup_quic_rules
        if [ "$SNI_QUIC_CONFIG_WARNED" -eq 0 ]; then
            echo "$(date '+%F %T') [WARN] Missing or invalid YAML sni_filter.uids/quic_ports lists; dedicated chains removed" >> "$MAIN_LOG"
            SNI_QUIC_CONFIG_WARNED=1
        fi
        return
    fi
    if [ "$sni_inspect_quic" != true ]; then
        SNI_QUIC_CONFIG_WARNED=0
        cleanup_quic_rules
        return
    fi
    sni_filter_state
    sni_state=$?
    if [ "$sni_state" -ne 0 ]; then
        cleanup_quic_rules
        if [ "$sni_state" -eq 2 ] && \
            [ "$SNI_QUIC_CONFIG_WARNED" -eq 0 ]; then
            echo "$(date '+%F %T') [WARN] QUIC inspection requested but SNI state is invalid; dedicated chains removed" >> "$MAIN_LOG"
            SNI_QUIC_CONFIG_WARNED=1
        elif [ "$sni_state" -eq 1 ]; then
            SNI_QUIC_CONFIG_WARNED=0
        fi
        return
    fi
    SNI_QUIC_CONFIG_WARNED=0
    # Rebuild from the current YAML set every pass: -C only proves expected rules
    # exist and cannot detect stale UID/port rules left after a config shrink.
    if ! ensure_quic4_rules; then
        cleanup_quic4_rules
        echo "$(date '+%F %T') [WARN] QUIC IPv4 NFQUEUE setup failed; AGHMOD_QUIC4 removed" >> "$MAIN_LOG"
    fi
    if ! ensure_quic6_rules; then
        cleanup_quic6_rules
        echo "$(date '+%F %T') [WARN] QUIC IPv6 NFQUEUE setup failed or ip6tables is unavailable; AGHMOD_QUIC6 removed" >> "$MAIN_LOG"
    fi
}

ensure_sni4_rules() {
    iptables -w 2 -t filter -L AGHMOD_SNI4 >/dev/null 2>&1 || \
        iptables -w 2 -t filter -N AGHMOD_SNI4 || return 1
    iptables -w 2 -t filter -F AGHMOD_SNI4 || return 1
    while iptables -w 2 -t filter -D OUTPUT -j AGHMOD_SNI4 >/dev/null 2>&1; do :; done
    iptables -w 2 -t filter -I OUTPUT -j AGHMOD_SNI4 || return 1

    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_tcp_rule iptables -A AGHMOD_SNI4 "$sni_port" "$sni_uid_segment" || { IFS=$old_ifs; return 1; }
            done
        else
            sni_tcp_rule iptables -A AGHMOD_SNI4 "$sni_port" '' || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

ensure_sni6_rules() {
    ip6tables -w 2 -t filter -L AGHMOD_SNI6 >/dev/null 2>&1 || \
        ip6tables -w 2 -t filter -N AGHMOD_SNI6 || return 1
    ip6tables -w 2 -t filter -F AGHMOD_SNI6 || return 1
    while ip6tables -w 2 -t filter -D OUTPUT -j AGHMOD_SNI6 >/dev/null 2>&1; do :; done
    ip6tables -w 2 -t filter -I OUTPUT -j AGHMOD_SNI6 || return 1

    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_tcp_rule ip6tables -A AGHMOD_SNI6 "$sni_port" "$sni_uid_segment" || { IFS=$old_ifs; return 1; }
            done
        else
            sni_tcp_rule ip6tables -A AGHMOD_SNI6 "$sni_port" '' || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

sni4_rules_are_valid() {
    iptables -w 2 -t filter -L AGHMOD_SNI4 >/dev/null 2>&1 || return 1
    iptables -w 2 -t filter -C OUTPUT -j AGHMOD_SNI4 >/dev/null 2>&1 || return 1
    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_tcp_rule iptables -C AGHMOD_SNI4 "$sni_port" "$sni_uid_segment" >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
            done
        else
            sni_tcp_rule iptables -C AGHMOD_SNI4 "$sni_port" '' >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

sni6_rules_are_valid() {
    ip6tables -w 2 -t filter -L AGHMOD_SNI6 >/dev/null 2>&1 || return 1
    ip6tables -w 2 -t filter -C OUTPUT -j AGHMOD_SNI6 >/dev/null 2>&1 || return 1
    old_ifs=$IFS
    IFS=,
    for sni_port in $sni_ports; do
        if [ -n "$sni_uid_range" ]; then
            for sni_uid_segment in $sni_uid_range; do
                sni_tcp_rule ip6tables -C AGHMOD_SNI6 "$sni_port" "$sni_uid_segment" >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
            done
        else
            sni_tcp_rule ip6tables -C AGHMOD_SNI6 "$sni_port" '' >/dev/null 2>&1 || { IFS=$old_ifs; return 1; }
        fi
    done
    IFS=$old_ifs
}

SNI_RULES_CONFIG_WARNED=0
maintain_sni_rules() {
    if ! sni_ports_are_valid; then
        cleanup_sni_rules
        if [ "$SNI_RULES_CONFIG_WARNED" -eq 0 ]; then
            echo "$(date '+%F %T') [WARN] Missing or invalid YAML sni_filter.uids/ports lists; dedicated chains removed" >> "$MAIN_LOG"
            SNI_RULES_CONFIG_WARNED=1
        fi
        return
    fi
    sni_filter_state
    sni_state=$?
    if [ "$sni_state" -ne 0 ]; then
        cleanup_sni_rules
        if [ "$sni_state" -eq 2 ]; then
            if [ "$SNI_RULES_CONFIG_WARNED" -eq 0 ]; then
                echo "$(date '+%F %T') [WARN] Invalid SNI filtering configuration; dedicated chains removed" >> "$MAIN_LOG"
                SNI_RULES_CONFIG_WARNED=1
            fi
        else
            SNI_RULES_CONFIG_WARNED=0
        fi
        return
    fi
    SNI_RULES_CONFIG_WARNED=0
    # Rebuild each dedicated chain from the current YAML set. The families stay
    # independent so missing IPv6 support cannot affect a working IPv4 chain.
    if ! ensure_sni4_rules; then
        cleanup_sni4_rules
        echo "$(date '+%F %T') [WARN] SNI IPv4 NFQUEUE setup failed; AGHMOD_SNI4 removed" >> "$MAIN_LOG"
    fi
    if ! ensure_sni6_rules; then
        cleanup_sni6_rules
        echo "$(date '+%F %T') [WARN] SNI IPv6 NFQUEUE setup failed or ip6tables is unavailable; AGHMOD_SNI6 removed" >> "$MAIN_LOG"
    fi
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
IPV6_NAT_UNSUPPORTED_WARNED=0
while true; do
    # 非 SNI 模块配置仍从 config.prop 读取；SNI/QUIC 规则列表只从 YAML 读取。
    # shellcheck disable=SC1091
    . "$AGH_DIR/scripts/config.prop"
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
        # unknown 时宁可放弃 AGH 接管，也不能让旧 AGH 规则继续抢占 53。
        2) cleanup_agh4_rules; log_box_dns_unknown 4 ;;
    esac
    box_dns6_active; v6_rc=$?
    case $v6_rc in
        0) [ "$IPV6_NAT_UNSUPPORTED" -eq 1 ] || cleanup_agh6_rules ;;
        1) rules6_are_valid || { ensure_ipv6_rules || :; } ;;
        # unknown 时不安装新规则，并清掉已有 AGH IPv6 DNS 规则。
        2)
            if [ "$IPV6_NAT_UNSUPPORTED" -eq 0 ]; then
                cleanup_agh6_rules
                log_box_dns_unknown 6
            fi
            ;;
        # nat 不可用时不能维护 AGHMOD_DNS6；mangle/TUN 探测仍在上方执行。
        3) : ;;
    esac
    if [ "$IPV6_NAT_UNSUPPORTED" -eq 1 ]; then
        if [ "$IPV6_NAT_UNSUPPORTED_WARNED" -eq 0 ]; then
            echo "$(date '+%F %T') [WARN] IPv6 NAT unsupported; AGH IPv6 DNS interception disabled" >> "$MAIN_LOG"
            IPV6_NAT_UNSUPPORTED_WARNED=1
        fi
    else
        IPV6_NAT_UNSUPPORTED_WARNED=0
    fi
    # DoT(853) 阻断独立维护：不依赖 box 接管状态，规则缺失即补齐。
    dot4_rules_valid || { ensure_dot4_rules || :; }
    dot6_rules_valid || { ensure_dot6_rules || :; }
    load_sni_rule_lists
    # SNI 链完全独立于 DNS、DoT 和 Box 链；禁用、配置错误或安装失败时
    # maintain_sni_rules 都会移除两个专用链及其 OUTPUT 跳转。
    maintain_sni_rules
    # QUIC 是独立 UDP 子功能：必须显式 inspect_quic=true，且复用 SNI queue_num。
    maintain_quic_rules
    sleep 60
done
