#!/system/bin/sh
# shellcheck disable=SC2034 # 由 Magisk/KernelSU 安装器读取。
SKIPUNZIP=1

# 多语言检测
locale=$(getprop persist.sys.locale | tr '[:upper:]' '[:lower:]')
[ -z "$locale" ] && locale="zh"
ui_print "- $locale"
case $locale in
  en*) language=en ;;
  *)   language=zh ;;
esac
i18n_print() {
  if [ "$language" = "zh" ]; then
    ui_print "$2"
  else
    ui_print "$1"
  fi
}

# 检测所有Hosts模块
i18n_print "- Checking for Hosts modules" "- 正在检测Hosts模块"
found_hosts=false;for module in /data/adb/modules/*;do [ -f "$module/system/etc/hosts" ]&&[ -f "$module/module.prop" ]&&{ [ "$found_hosts" = false ]&&i18n_print "- Found Hosts modules, auto-removing:" "- 发现Hosts模块，正在自动移除:"&&found_hosts=true;ui_print "  $(grep_prop name "$module/module.prop")";touch "$module/remove";};done
[ "$found_hosts" = true ]&&i18n_print "- Conflicting modules have been marked for removal. Please reboot after installation." "- 冲突模块已标记移除，安装完成后请重启设备。"

AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
BACKUP_DIR="$AGH_DIR/backup"
ADGPATH="/data/adb/modules/AdGuardHome"

# 停止旧版模块脚本并等待其退出
i18n_print "- Stopping module service processes" "- 正在终止模块服务进程"
pkill -TERM -f '[/]iptables.sh'
pkill -TERM -f '[/]NoAdsService.sh'
pkill -TERM -f '[/]ProxyConfig.sh'
pkill -TERM -f '[/]ModuleMOD.sh'
module_processes_stopped() {
    ! pgrep -f '[/]iptables.sh' >/dev/null 2>&1 &&
    ! pgrep -f '[/]NoAdsService.sh' >/dev/null 2>&1 &&
    ! pgrep -f '[/]ProxyConfig.sh' >/dev/null 2>&1 &&
    ! pgrep -f '[/]ModuleMOD.sh' >/dev/null 2>&1
}
i=0
while [ "$i" -lt 5 ]; do
    module_processes_stopped && break
    sleep 1
    i=$((i+1))
done
if ! module_processes_stopped; then
    pkill -KILL -f '[/]iptables.sh'
    pkill -KILL -f '[/]NoAdsService.sh'
    pkill -KILL -f '[/]ProxyConfig.sh'
    pkill -KILL -f '[/]ModuleMOD.sh'
fi
if ! module_processes_stopped; then
    ui_print "- Module service processes did not exit; installation aborted."
    ui_print "- 模块服务进程未退出，安装已中止。"
    printf '%s [ERROR] 模块服务进程未退出，已中止安装。\n' "$(date '+%F %T')" >> "$AGH_DIR/agh.log"
    exit 1
fi

# 守护脚本退出后停止AdGuardHome
if [ -d "$AGH_DIR" ]; then
    i18n_print "- Stopping all AdGuard Home processes" "- 正在终止AdGuard Home进程"
    pkill -9 "AdGuardHome"
    agh_stopped=false
    w=0
    while pgrep -x "AdGuardHome" >/dev/null 2>&1; do
        [ "$w" -ge 3 ] && break
        sleep 1
        w=$((w + 1))
    done
    if pgrep -x "AdGuardHome" >/dev/null 2>&1; then
        i18n_print "- AdGuardHome did not stop, aborting installation" "- AdGuardHome未退出，已中止安装"
        exit 1
    fi
fi

# 清理本模块新规则；旧通用规则所有权不明，禁止触碰
while iptables -w 2 -t nat -D OUTPUT -j AGHMOD_DNS4 >/dev/null 2>&1; do :; done
iptables -w 2 -t nat -F AGHMOD_DNS4 >/dev/null 2>&1
iptables -w 2 -t nat -X AGHMOD_DNS4 >/dev/null 2>&1
while ip6tables -w 2 -D OUTPUT -j AGHMOD_DNS6 >/dev/null 2>&1; do :; done
ip6tables -w 2 -F AGHMOD_DNS6 >/dev/null 2>&1
ip6tables -w 2 -X AGHMOD_DNS6 >/dev/null 2>&1

i18n_print "- Extracting basic module files" "- 正在解压模块基本文件"
for file in uninstall.sh module.prop service.sh action.sh; do
  unzip -o "$ZIPFILE" "$file" -d "$MODPATH"
done

# 删除被锁定的残留文件
[ -f "$AGH_DIR/scripts/NoAdsService.sh" ] && {
    i18n_print "- Removing locked residual files" "- 正在删除被锁定的残留文件"
    c=0
    u=0
    cleanup_paths="$AGH_DIR/.noads_paths.$$"
    cleanup_files="$AGH_DIR/.noads_files.$$"
    grep 'block_ad' "$AGH_DIR/scripts/NoAdsService.sh" | grep -o '".*"' | tr -d '"' > "$cleanup_paths"
    : > "$cleanup_files"
    while IFS= read -r p; do
        [ -n "$p" ] && [ -e "$p" ] && find "$p" \( -type f -o -type d \) >> "$cleanup_files"
    done < "$cleanup_paths"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        c=$((c+1))
        if [ -d "$f" ]; then
            if lsattr -d "$f" | grep -q "i-"; then
                chattr -i "$f"
                rmdir "$f" && u=$((u+1))
            fi
        elif lsattr "$f" | grep -q "i-"; then
            chattr -i "$f"
            rm -f "$f"
            u=$((u+1))
        fi
    done < "$cleanup_files"
    rm -f "$cleanup_paths" "$cleanup_files"
    i18n_print "- Removed $u locked files out of $c scanned items" "- 从 $c 个文件中删除了 $u 个锁定文件"
}

# 检查是否首次安装
if [ -d "$AGH_DIR" ]; then
  i18n_print "- Backing up configuration" "- 正在备份配置文件"
  mkdir -p "$BACKUP_DIR"
  [ -f "$BIN_DIR/AdGuardHome.yaml" ] && cp -f "$BIN_DIR/AdGuardHome.yaml" "$BACKUP_DIR/"
  [ -f "$SCRIPT_DIR/config.prop" ] && cp -f "$SCRIPT_DIR/config.prop" "$BACKUP_DIR/"
  [ -f "$SCRIPT_DIR/NoAdsService.sh" ] && cp -f "$SCRIPT_DIR/NoAdsService.sh" "$BACKUP_DIR/"
fi

# 解锁脚本防篡改保护
if [ -d "$SCRIPT_DIR" ]; then
    i18n_print "- Unlocking old script files" "- 正在解锁旧脚本文件"
    find "$AGH_DIR/scripts" "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} \;
fi

# 清除旧模块残留
if [ -d "$AGH_DIR/ifw" ] || [ -d "$AGH_DIR/scripts" ] || [ -d "$BIN_DIR/agh_pid" ] || [ -d "$BIN_DIR/data/filters" ]; then
  i18n_print "- Cleaning up old module residues" "- 正在清理旧模块残留"
  rm -rf "$AGH_DIR/ifw" "$AGH_DIR/scripts" "$BIN_DIR/agh_pid" "$BIN_DIR/data/filters"
fi

# 创建目录并解压文件
mkdir -p "$AGH_DIR" "$BIN_DIR" "$SCRIPT_DIR" "$BACKUP_DIR"
i18n_print "- Extracting AdGuardHome files" "- 正在解压 AdGuardHome 文件"
unzip -o "$ZIPFILE" "scripts/*" -d "$AGH_DIR"
unzip -o "$ZIPFILE" "bin/*" -d "$AGH_DIR"
i18n_print "- Setting permissions" "- 设置权限"
find "$AGH_DIR" -type d -exec chmod 0700 {} \;
chmod +x "$BIN_DIR/AdGuardHome" 
chmod +x "$SCRIPT_DIR"/*.sh
chown root:net_raw "$BIN_DIR/AdGuardHome"

# 执行脚本防篡改保护
i18n_print "- Locking script files" "- 正在锁定脚本文件"
find "$SCRIPT_DIR" -type f -name "*.sh" -exec chattr +i {} \;

# 正在保留配置文件
if [ -f "$BACKUP_DIR/config.prop" ]; then
  i18n_print "- Preserving configuration file" "- 正在保留配置文件"
  cp -f "$BACKUP_DIR/config.prop" "$SCRIPT_DIR/"
fi
i18n_print "- Installation complete. Reboot device." "- 安装完成，请重启设备。"
