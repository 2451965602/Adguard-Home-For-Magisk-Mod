#!/system/bin/sh
CONFIG_FILE="$(dirname "$0")/config.prop"
AGH_DIR="$(dirname "$(dirname "$0")")"
# shellcheck disable=SC1090
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"
[ "$(pgrep -f "$0" | wc -l)" -gt 1 ] && exit

# 默认的单个空格代表未配置代理地址。
PROXY_URL_VALUE=$(printf '%s' "${PROXY_URL-}" | sed 's/[[:space:]]//g')

restart_service() {
    case "$1" in
        box_bll) /data/adb/box_bll/scripts/box.service restart ;;
        box) /data/adb/box/scripts/box.service restart ;;
        clash) /data/clash/scripts/clash.service -k && /data/clash/scripts/clash.service -s ;;
        Clash)
            /data/adb/modules/Clash/Scripts/Clash.Service stop
            /data/adb/modules/Clash/Scripts/Clash.Service start
            ;;
    esac
    for s in 1 0; do
        settings put global airplane_mode_on "$s"
        am broadcast -a android.intent.action.AIRPLANE_MODE
    done
}

# 严格跟踪顶层 dns 块和四个直接列表键。
dns_transform() {
    transform_mode=$1
    transform_file=$2
    # redir_port is supplied by config.prop.
    # shellcheck disable=SC2154
    awk -v mode="$transform_mode" -v port="$redir_port" '
        function top(line) { return line ~ /^[^[:space:]#][^:]*:/ }
        function target(k) { return k == "direct-nameserver" || k == "proxy-server-nameserver" || k == "nameserver" || k == "default-nameserver" }
        function current_local_item(line) { return line ~ "^    -[ ]*127[.]0[.]0[.]1:" port "([ ]*#.*)?$" }
        function managed_local_item(line) { return line ~ "^    -[ ]*127[.]0[.]0[.]1:[0-9][0-9]*([ ]*#.*)?$" }
        function list_item(line) { return line ~ /^    -[[:space:]]/ }
        function comment_item(line) { return line ~ /^    #[[:space:]]*-/ }
        function marker(line) { return line ~ /^    #[[:space:]]*AdGuardHome managed DNS([[:space:]]+disabled)?[[:space:]]*$/ }
        function enhanced_marker(line) { return line ~ /^  #[[:space:]]*AdGuardHome managed enhanced-mode[|]/ }
        {
            raw[NR] = $0
            if (top($0)) {
                name = $0
                sub(/:.*/, "", name)
                in_dns = (name == "dns")
                current = ""
            } else if (in_dns && $0 ~ /^  [^[:space:]#][^:]*:/) {
                key = $0
                sub(/^  /, "", key)
                sub(/:.*/, "", key)
                if (target(key)) current = key
                else current = ""
            }
            section[NR] = current
            dns_line[NR] = in_dns
            if (in_dns && $0 ~ /^  enhanced-mode:[[:space:]]*redir-host([[:space:]]*#.*)?$/)
                has_enhanced = 1
            if (current != "" && list_item($0)) {
                has_any_list = 1
                has_list[current] = 1
                if (managed_local_item($0)) has_local[current] = 1
                else if ($0 !~ /^    #[[:space:]]/) has_other[current] = 1
            }
        }
        END {
            need = 0
            # default-nameserver 是 mihomo 的引导 DNS，只处理可识别的旧迁移格式。
            for (s in has_list)
                if (s != "default-nameserver" && (!has_local[s] || has_other[s])) need = 1
            # 带模块 marker 的 localhost 必须使用当前端口；未带 marker 的用户项可保留原端口。
            for (i = 1; i <= NR; i++) {
                if (dns_line[i] && section[i] != "" && marker(raw[i])) {
                    n = raw[i + 1]
                    if (managed_local_item(n) && !current_local_item(n)) need = 1
                }
            }
            # default-nameserver 仅在有模块 marker 时才需要处理（清理旧注入）。
            for (i = 1; i <= NR; i++) {
                if (dns_line[i] && section[i] == "default-nameserver" && marker(raw[i])) need = 1
            }
            if (has_any_list && !has_enhanced) need = 1
            if (mode == "check") exit need ? 1 : 0
            for (i = 1; i <= NR; i++) {
                l = raw[i]
                s = section[i]
                if (mode == "clean" && dns_line[i] && enhanced_marker(l) &&
                    i < NR && raw[i + 1] ~ /^  enhanced-mode:[[:space:]]*redir-host([[:space:]]*#.*)?$/) {
                    original = l
                    sub(/^  #[[:space:]]*AdGuardHome managed enhanced-mode[|]/, "", original)
                    print original
                    i++
                    continue
                }
                if (mode == "process" && dns_line[i] && enhanced_marker(l) &&
                    i < NR && raw[i + 1] ~ /^  enhanced-mode:[[:space:]]*redir-host([[:space:]]*#.*)?$/) {
                    print l
                    print raw[i + 1]
                    i++
                    continue
                }
                if ((mode == "clean" || mode == "process") && dns_line[i] && enhanced_marker(l)) {
                    print l
                    if (i < NR) { print raw[i + 1]; i++ }
                    continue
                }
                # marker 处理（所有 section、两种模式）：
                # - marker + AGH 地址：default-nameserver 两种模式都丢弃（不注入）；
                #   其他 section：process 更新为当前端口，clean 成对丢弃。
                # - disabled marker + 被注释用户项：clean 或 default-nameserver 恢复用户项。
                # - clean 下孤立 marker 一律移除。
                if (s != "" && marker(l)) {
                    n = raw[i + 1]
                    if (managed_local_item(n)) {
                        if (mode == "process" && s != "default-nameserver") {
                            print l
                            print "    - 127.0.0.1:" port
                        }
                        i++
                        continue
                    }
                    if ((mode == "clean" || s == "default-nameserver") && l ~ /disabled/ && n ~ /^    #[[:space:]]*-[[:space:]]+/) {
                        restored = n
                        sub(/^    #[[:space:]]*/, "    ", restored)
                        print restored
                        i++
                        continue
                    }
                    if (mode == "clean" || s == "default-nameserver") continue
                    print l
                    continue
                }
                if (mode == "process" && dns_line[i] && l ~ /^  enhanced-mode:/ && l !~ /:[[:space:]]*redir-host([[:space:]]*#.*)?$/ && has_any_list) {
                    print "  # AdGuardHome managed enhanced-mode|" l
                    print "  enhanced-mode: redir-host"
                    continue
                }
                if (s != "" && list_item(l)) {
                    # default-nameserver 不注入 AGH 地址（mihomo 要求纯 IP 引导）。
                    # 无 marker 的用户条目（含 localhost）一律原样保留，不做迁移猜测。
                    if (s == "default-nameserver") {
                        print l
                        continue
                    }
                    if (mode == "clean") {
                        # 仅清理紧邻模块 marker 的 AGH 注入项；孤立 localhost 保留。
                        print l
                        continue
                    }
                    if (!inserted[s] && !has_local[s]) {
                        print "    # AdGuardHome managed DNS"
                        print "    - 127.0.0.1:" port
                        inserted[s] = 1
                    }
                    if (managed_local_item(l) || l ~ /^    #[[:space:]]/) print l
                    else {
                        print "    # AdGuardHome managed DNS disabled"
                        print "    # " substr(l, 5)
                    }
                    continue
                }
                print l
            }
        }
    ' "$transform_file"
}

# 尽力保留原文件属性；属性工具不可用时不阻断主流程。
replace_config_file() {
    replace_target=$1
    replace_tmp=$2
    replace_mode=$(stat -c '%a' "$replace_target" 2>/dev/null) || replace_mode=
    replace_uid=$(stat -c '%u' "$replace_target" 2>/dev/null) || replace_uid=
    replace_gid=$(stat -c '%g' "$replace_target" 2>/dev/null) || replace_gid=
    [ -z "$replace_mode" ] || chmod "$replace_mode" "$replace_tmp" 2>/dev/null || :
    if [ -n "$replace_uid" ] && [ -n "$replace_gid" ]; then
        chown "$replace_uid:$replace_gid" "$replace_tmp" 2>/dev/null || \
            chown "$replace_uid.$replace_gid" "$replace_tmp" 2>/dev/null || :
    fi
    mv "$replace_tmp" "$replace_target" || return 1
    if command -v restorecon >/dev/null 2>&1; then
        restorecon "$replace_target" >/dev/null 2>&1 || :
    fi
    return 0
}

# URL+DNS 合并转换：先 URL 阶段再 DNS 阶段，全部在临时文件中完成，
# 单次 mv 原子替换原文件，杜绝部分提交。
# 返回：0=已修改，1=无变化，2=失败。
rewrite_config() {
    rewrite_mode=$1
    rewrite_file=$2
    rewrite_tmp=
    if [ "$rewrite_mode" = "clean" ] || [ -n "$PROXY_URL_VALUE" ]; then
        # URL 阶段：marker 配对恢复/刷新，孤立 marker 在 clean 下移除。
        rewrite_tmp=$(mktemp "${rewrite_file}.tmp.XXXXXX") || return 2
        rewrite_proxy_url "$rewrite_mode" "$rewrite_file" "$rewrite_tmp" || \
            { rm -f "$rewrite_tmp"; return 2; }
        dns_source=$rewrite_tmp
    else
        dns_source=$rewrite_file
    fi
    # DNS 阶段：读写另一个临时文件，避免读写同一文件。
    rewrite_tmp2=$(mktemp "${rewrite_file}.tmp.XXXXXX") || { rm -f "$rewrite_tmp"; return 2; }
    dns_transform "$rewrite_mode" "$dns_source" > "$rewrite_tmp2" || \
        { rm -f "$rewrite_tmp" "$rewrite_tmp2"; return 2; }
    [ -n "$rewrite_tmp" ] && rm -f "$rewrite_tmp"
    if cmp -s "$rewrite_file" "$rewrite_tmp2"; then rm -f "$rewrite_tmp2"; return 1; fi
    replace_config_file "$rewrite_file" "$rewrite_tmp2" || { rm -f "$rewrite_tmp2"; return 2; }
    return 0
}

# proxy-providers 顶层块内的 URL 转换（管道式：$2 输入 -> $3 输出）。
# process：无 marker 的 url 行加 marker 并注入新 URL；marker+url 配对刷新 URL 值。
# clean：marker+url 配对恢复原始 URL 行；孤立 marker 移除。
rewrite_proxy_url() {
    rewrite_mode=$1
    rewrite_in=$2
    rewrite_out=$3
    awk -v mode="$rewrite_mode" -v new_url="$PROXY_URL_VALUE" '
        function top(line) { return line ~ /^[^[:space:]#][^:]*:/ }
        {
            raw[NR] = $0
            if (top($0)) {
                name = $0
                sub(/:.*/, "", name)
                in_providers = (name == "proxy-providers")
                provider = 0
            } else if (in_providers && $0 ~ /^  [^[:space:]#][^:]*:/) {
                provider = 1
            }
            is_url[NR] = (in_providers && provider && $0 ~ /^    url:[[:space:]]*/)
            is_marker[NR] = (in_providers && provider && $0 ~ /^    #[[:space:]]*AdGuardHome managed proxy-url[|]/)
        }
        END {
            for (i = 1; i <= NR; i++) {
                l = raw[i]
                if (is_marker[i] && is_url[i + 1]) {
                    if (mode == "clean") {
                        orig = l
                        sub(/^    #[[:space:]]*AdGuardHome managed proxy-url[|]/, "", orig)
                        print orig
                    } else {
                        print l
                        prefix = raw[i + 1]
                        sub(/url:.*/, "", prefix)
                        print prefix "url: \"" new_url "\""
                    }
                    i++
                    continue
                }
                if (is_marker[i]) {
                    if (mode == "clean") continue
                    print l
                    continue
                }
                if (is_url[i] && mode == "process") {
                    print "    # AdGuardHome managed proxy-url|" l
                    prefix = l
                    sub(/url:.*/, "", prefix)
                    print prefix "url: \"" new_url "\""
                    continue
                }
                print l
            }
        }
    ' "$rewrite_in" > "$rewrite_out"
}

# 只检查 proxy-providers 顶层块内 provider 直接的四空格 url。
proxy_url_present() {
    awk -v wanted_url="$PROXY_URL_VALUE" '
        function top(line) { return line ~ /^[^[:space:]#][^:]*:/ }
        {
            if (top($0)) {
                name = $0
                sub(/:.*/, "", name)
                in_providers = (name == "proxy-providers")
                provider = 0
            } else if (in_providers && $0 ~ /^  [^[:space:]#][^:]*:/) {
                provider = 1
            }
            if (in_providers && provider && $0 ~ /^    url:[[:space:]]*/) {
                provider_urls++
                val = $0
                sub(/^    url:[[:space:]]*/, "", val)
                sub(/[[:space:]]*$/, "", val)
                gsub(/^"|"$/, "", val)
                if (val != wanted_url) incomplete = 1
            }
        }
        END { exit provider_urls > 0 && !incomplete ? 0 : 1 }
    ' "$1"
}

is_standard_config() {
    [ -f "$1" ] || return 1
    if [ -n "$PROXY_URL_VALUE" ] && ! proxy_url_present "$1"; then return 1; fi
    dns_transform check "$1" > /dev/null || return 1
    return 0
}

clean_config() {
    [ -f "$1" ] || return 1
    rewrite_config clean "$1"
}

process_config() {
    is_standard_config "$1" && return 1
    rewrite_config process "$1"
}

# AGH 就绪 = 进程存在且 redir_port 在 127.0.0.1/wildcard 上 TCP 和 UDP 均监听。
# 按列解析 /proc/net：本地地址列须为 0100007F 或 00000000 且含 :HEXPORT。
agh_ready() {
    pgrep -x "AdGuardHome" >/dev/null 2>&1 || return 1
    hex_port=$(printf '%04X' "$redir_port")
    # TCP：本地地址为 IPv4 127.0.0.1/wildcard + 端口，状态 0A (LISTEN)
    awk -v p="$hex_port" '
        $2 ~ /^(0100007F|00000000):/ {
            split($2, a, ":")
            if (toupper(a[2]) == p && $4 == "0A") { found=1; exit }
        }
        END { exit !found }
    ' /proc/net/tcp 2>/dev/null || return 1
    # UDP：本地地址为 IPv4 127.0.0.1/wildcard + 端口，无对端
    awk -v p="$hex_port" '
        $2 ~ /^(0100007F|00000000):/ {
            split($2, a, ":")
            if (toupper(a[2]) == p && $3 ~ /:0000$/) { found=1; exit }
        }
        END { exit !found }
    ' /proc/net/udp 2>/dev/null
}

# 等待 AGH 就绪（有限重试：3 次 x 2 秒）。
wait_agh_ready() {
    i=0
    while [ "$i" -lt 3 ]; do
        agh_ready && return 0
        i=$((i + 1))
        sleep 2
    done
    return 1
}

process_configs() {
    service_key=$1
    case "$service_key" in
        box_bll) config_glob='/data/adb/box_bll/clash/*.yaml' ;;
        box) config_glob='/data/adb/box/mihomo/*.yaml' ;;
        clash) config_glob='/data/clash/*.yaml' ;;
        Clash) config_glob='/data/media/0/Android/Clash/*.yaml' ;;
        *) return 1 ;;
    esac
    need_restart=0
    # 修改 box 配置前确认 AGH 已运行，避免 box 重启后上游全部失效导致 DNS 中断。
    if [ "$2" != "--clean" ] && ! agh_ready && ! wait_agh_ready; then
        echo "$(date '+%F %T') [WARN] AdGuardHome 未就绪，跳过代理配置修改，30 秒后重试。" >> "$AGH_DIR/agh.log" 2>/dev/null
        retry_soon=1
        return 0
    fi
    # shellcheck disable=SC2086
    for config_file in $config_glob; do
        [ -f "$config_file" ] || continue
        if [ "$2" = "--clean" ]; then
            if clean_config "$config_file"; then
                need_restart=1
            fi
            continue
        fi
        process_config "$config_file" && need_restart=1
    done
    [ "$need_restart" -eq 1 ] && restart_service "$service_key"
}

while :; do
    retry_soon=0
    process_configs box_bll "$1"
    process_configs box "$1"
    process_configs clash "$1"
    process_configs Clash "$1"
    [ "$1" = "--clean" ] && exit 0
    # AGH 未就绪导致跳过时，30 秒后重试；否则按常规长周期轮询。
    if [ "$retry_soon" -eq 1 ]; then sleep 30; else sleep 36000; fi
done
