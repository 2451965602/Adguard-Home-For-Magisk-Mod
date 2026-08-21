#!/system/bin/sh
CONFIG_FILE="$(dirname "$0")/config.prop"
AGH_DIR="$(dirname "$(dirname "$0")")"
# shellcheck disable=SC1090
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

# 单实例锁：mkdir 原子操作，不依赖 pgrep 进程名匹配
# （shell 命令替换 fork 的子进程会复制 cmdline，pgrep 会误计自身实例）。
LOCK_DIR="$AGH_DIR/.proxycfg.lock"
if [ -d "$LOCK_DIR" ]; then
    # 超过 10 分钟视为残留锁（进程被 kill -9 后遗留），强制清除
    [ -n "$(find "$LOCK_DIR" -maxdepth 0 -mmin +10 2>/dev/null)" ] && rm -rf "$LOCK_DIR"
fi
mkdir "$LOCK_DIR" 2>/dev/null || exit
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT

# 端口真相源：AGH 实际加载的 AdGuardHome.yaml 中 dns.port。
# config.prop 可能因 service.sh 重试循环漂移，yaml 才是运行实例的真实端口。
AGH_YAML_PORT=$(awk '/^dns:[[:space:]]*$/{f=1;next} f&&/^  port:[[:space:]]*[0-9]+/{print $2; exit}' "$AGH_DIR/bin/AdGuardHome.yaml" 2>/dev/null)
[ -n "$AGH_YAML_PORT" ] && redir_port="$AGH_YAML_PORT"

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
        # dns 块内 4 空格直接列表 section
        function dns_target(k) { return k == "direct-nameserver" || k == "proxy-server-nameserver" || k == "nameserver" || k == "default-nameserver" }
        # sniffer 块内 4 空格直接列表 section
        function sniffer_target(k) { return k == "skip-domain" }
        function current_local_item(line) { return line ~ "^    -[ ]*127[.]0[.]0[.]1:" port "([ ]*#.*)?$" }
        function managed_local_item(line) { return line ~ "^    -[ ]*127[.]0[.]0[.]1:[0-9][0-9]*([ ]*#.*)?$" }
        function list_item(line) { return line ~ /^    -[[:space:]]/ }
        function comment_item(line) { return line ~ /^    #[[:space:]]*-/ }
        # dns 列表 active marker（不含 disabled）
        function active_dns_marker(line) { return line ~ /^    #[[:space:]]*AdGuardHome managed DNS[[:space:]]*$/ }
        # dns 列表 disabled marker
        function disabled_dns_marker(line) { return line ~ /^    #[[:space:]]*AdGuardHome managed DNS[[:space:]]+disabled[[:space:]]*$/ }
        # dns 列表任意 marker
        function dns_marker(line) { return active_dns_marker(line) || disabled_dns_marker(line) }
        # sniffer.skip-domain active marker
        function active_sniffer_marker(line) { return line ~ /^    #[[:space:]]*AdGuardHome managed sniffer[.]skip-domain[[:space:]]*$/ }
        # sniffer.skip-domain disabled marker
        function disabled_sniffer_marker(line) { return line ~ /^    #[[:space:]]*AdGuardHome managed sniffer[.]skip-domain[[:space:]]+disabled[[:space:]]*$/ }
        # sniffer.skip-domain 任意 marker
        function sniffer_marker(line) { return active_sniffer_marker(line) || disabled_sniffer_marker(line) }
        function enhanced_marker(line) { return line ~ /^  #[[:space:]]*AdGuardHome managed enhanced-mode[|]/ }
        {
            raw[NR] = $0
            if (top($0)) {
                name = $0
                sub(/:.*/, "", name)
                top_block = (name == "dns" || name == "sniffer") ? name : ""
                target_id = ""
            } else if (top_block != "" && $0 ~ /^  [^[:space:]#][^:]*:/) {
                key = $0
                sub(/^  /, "", key)
                sub(/:.*/, "", key)
                if (top_block == "dns" && dns_target(key)) {
                    target_id = "dns:" key
                } else if (top_block == "sniffer" && sniffer_target(key)) {
                    target_id = "sniffer:" key
                } else {
                    target_id = ""
                }
            }
            section[NR] = target_id
            block[NR] = top_block
            # 记录所有出现的 target section（含空/仅注释的 section）
            if (target_id != "") seen_target[target_id] = 1
            if (top_block == "dns" && $0 ~ /^  enhanced-mode:[[:space:]]*redir-host([[:space:]]*#.*)?$/)
                has_enhanced = 1
            if (target_id != "" && list_item($0)) {
                if (top_block == "dns") has_dns_list = 1
                if (top_block == "sniffer") has_sniffer_list = 1
                has_list[target_id] = 1
                # managed localhost 不计入 has_other（有效配对的注入行本身）
                if (!managed_local_item($0) && $0 !~ /^    #[[:space:]]/) has_other[target_id] = 1
            }
        }
        END {
            need = 0
            # 有效 marker 配对统计：active marker 紧邻当前端口才算 valid_managed_pair
            # 在 END 段计算（扫描阶段 raw[NR+1] 尚未读入）
            for (i = 1; i <= NR; i++) {
                s = section[i]
                if (s == "" || s == "dns:default-nameserver") continue
                l = raw[i]
                is_active_dns = active_dns_marker(l)
                is_active_sniffer = active_sniffer_marker(l)
                if ((s ~ /^dns:/ && is_active_dns) || (s ~ /^sniffer:/ && is_active_sniffer)) {
                    n = raw[i + 1]
                    if (current_local_item(n)) valid_managed_pair[s] = 1
                }
            }
            # 直接列表 section：对所有 seen_target 检查有效配对
            for (tid in seen_target) {
                if (tid ~ /^dns:default-nameserver$/) continue
                if (!valid_managed_pair[tid] || has_other[tid]) need = 1
            }
            # marker 配对端口校验：active marker 紧邻 managed localhost 但端口非当前则 need
            for (i = 1; i <= NR; i++) {
                l = raw[i]
                s = section[i]
                if (s == "" || s == "dns:default-nameserver") continue
                is_active_dns = active_dns_marker(l)
                is_active_sniffer = active_sniffer_marker(l)
                if ((s ~ /^dns:/ && is_active_dns) || (s ~ /^sniffer:/ && is_active_sniffer)) {
                    n = raw[i + 1]
                    if (managed_local_item(n) && !current_local_item(n)) need = 1
                }
            }
            # default-nameserver 仅在有 marker 时处理
            for (i = 1; i <= NR; i++) {
                if (section[i] == "dns:default-nameserver" && dns_marker(raw[i])) need = 1
            }
            if (has_dns_list && !has_enhanced) need = 1
            if (mode == "check") exit need ? 1 : 0
            for (i = 1; i <= NR; i++) {
                l = raw[i]
                s = section[i]
                # enhanced-mode marker 处理（不变）
                if (mode == "clean" && block[i] == "dns" && enhanced_marker(l) &&
                    i < NR && raw[i + 1] ~ /^  enhanced-mode:[[:space:]]*redir-host([[:space:]]*#.*)?$/) {
                    original = l
                    sub(/^  #[[:space:]]*AdGuardHome managed enhanced-mode[|]/, "", original)
                    print original
                    i++
                    continue
                }
                if (mode == "process" && block[i] == "dns" && enhanced_marker(l) &&
                    i < NR && raw[i + 1] ~ /^  enhanced-mode:[[:space:]]*redir-host([[:space:]]*#.*)?$/) {
                    print l
                    print raw[i + 1]
                    i++
                    continue
                }
                if ((mode == "clean" || mode == "process") && block[i] == "dns" && enhanced_marker(l)) {
                    print l
                    if (i < NR) { print raw[i + 1]; i++ }
                    continue
                }
                # dns 列表 marker 处理（命名空间隔离：仅 dns:* section）
                if (s ~ /^dns:/ && s != "dns:default-nameserver" && dns_marker(l)) {
                    n = raw[i + 1]
                    if (managed_local_item(n)) {
                        if (mode == "process") {
                            print l
                            print "    - 127.0.0.1:" port
                        }
                        i++
                        continue
                    }
                    if (mode == "clean" && l ~ /disabled/ && n ~ /^    #[[:space:]]*-[[:space:]]+/) {
                        restored = n
                        sub(/^    #[[:space:]]*/, "    ", restored)
                        print restored
                        i++
                        continue
                    }
                    if (mode == "clean") continue
                    print l
                    continue
                }
                # sniffer.skip-domain marker 处理
                if (s == "sniffer:skip-domain" && sniffer_marker(l)) {
                    n = raw[i + 1]
                    if (managed_local_item(n)) {
                        if (mode == "process") {
                            print l
                            print "    - 127.0.0.1:" port
                        }
                        i++
                        continue
                    }
                    if (mode == "clean" && l ~ /disabled/ && n ~ /^    #[[:space:]]*-[[:space:]]+/) {
                        restored = n
                        sub(/^    #[[:space:]]*/, "    ", restored)
                        print restored
                        i++
                        continue
                    }
                    if (mode == "clean") continue
                    print l
                    continue
                }
                # default-nameserver marker 处理（两种模式都丢弃 AGH 注入）
                if (s == "dns:default-nameserver" && dns_marker(l)) {
                    n = raw[i + 1]
                    if (managed_local_item(n)) { i++; continue }
                    if (l ~ /disabled/ && n ~ /^    #[[:space:]]*-[[:space:]]+/) {
                        restored = n
                        sub(/^    #[[:space:]]*/, "    ", restored)
                        print restored
                        i++
                        continue
                    }
                    continue
                }
                if (mode == "process" && block[i] == "dns" && l ~ /^  enhanced-mode:/ && l !~ /:[[:space:]]*redir-host([[:space:]]*#.*)?$/ && has_dns_list) {
                    print "  # AdGuardHome managed enhanced-mode|" l
                    print "  enhanced-mode: redir-host"
                    continue
                }
                # 直接列表项处理（dns + sniffer）
                if (s != "" && s != "dns:default-nameserver" && list_item(l)) {
                    if (mode == "clean") {
                        print l
                        continue
                    }
                    # 注入条件：当前 section 无有效 marker+当前端口配对
                    if (!inserted[s] && !valid_managed_pair[s]) {
                        mk = (s == "sniffer:skip-domain") ? "    # AdGuardHome managed sniffer.skip-domain" : "    # AdGuardHome managed DNS"
                        print mk
                        print "    - 127.0.0.1:" port
                        inserted[s] = 1
                    }
                    # 无 marker 的旧端口 localhost 视为用户项，注释保留
                    if (managed_local_item(l) && !current_local_item(l)) {
                        mk = (s == "sniffer:skip-domain") ? "    # AdGuardHome managed sniffer.skip-domain disabled" : "    # AdGuardHome managed DNS disabled"
                        print mk
                        print "    # " substr(l, 5)
                    } else if (managed_local_item(l) || l ~ /^    #[[:space:]]/) print l
                    else {
                        mk = (s == "sniffer:skip-domain") ? "    # AdGuardHome managed sniffer.skip-domain disabled" : "    # AdGuardHome managed DNS disabled"
                        print mk
                        print "    # " substr(l, 5)
                    }
                    continue
                }
                # default-nameserver 列表项：不注入 AGH，原样保留
                if (s == "dns:default-nameserver" && list_item(l)) {
                    print l
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

# AGH 就绪 = redir_port 在 127.0.0.1/wildcard 上 TCP 和 UDP 均监听。
# 按列解析 /proc/net：本地地址列须为 0100007F 或 00000000 且含 :HEXPORT。
# 不用 pgrep 判存活：开机早期 KernelSU 环境下 pgrep 可能不可用（返回 127 被
# 误判为进程不存在，导致配置修改被永久跳过）。端口监听即就绪。
agh_ready() {
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
