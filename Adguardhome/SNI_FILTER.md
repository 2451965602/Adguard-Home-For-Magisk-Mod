# SNI 过滤

模块脚本维护 TCP SNI 的 `AGHMOD_SNI4`、`AGHMOD_SNI6` 和 QUIC/DoQ UDP 的
`AGHMOD_QUIC4`、`AGHMOD_QUIC6` 四个 `filter/OUTPUT` 专用链。
默认不启用；custom core 的 YAML 中 `sni_filter.enabled: true`，或
`filtering.blocking_mode: strong` 时才会安装。UID 范围、TCP 端口和 QUIC 端口列表
均以 `AdGuardHome.yaml` 的 `sni_filter.uids`、`sni_filter.ports` 和
`sni_filter.quic_ports` 为唯一运行时规则源；`config.prop` 不再配置这些列表。
非空 UID 列表和端口列表都必须是简单 block 列表。脚本只接受 UID
`"start-end"` 和十进制端口项；`uids: []` 表示全部进程，不添加
`-m owner/--uid-owner` 匹配。缺失列表或其他 YAML 语法会清理相应专用链，并记录一次
警告，不影响基础 DNS 规则。NFQUEUE 编号仍从 YAML 的
`sni_filter.queue_num` 读取。

默认 UID 列表为普通应用 `"10000-19999"` 和 Android 用户 0 的浏览器隔离进程
`"90000-99999"`。不要擅自扩大范围覆盖工作资料或其他 Android 用户 UID。`ports`
配置 TCP SNI 目标端口，`quic_ports` 配置 QUIC/DoQ UDP 目标端口。

```yaml
sni_filter:
  enabled: false
  inspect_quic: true
  queue_num: 7
  uids:
    - "10000-19999"
    - "90000-99999"
  ports:
    - 443
  quic_ports:
    - 443
```

列表不支持嵌套、锚点/别名或多行标量；UID 项必须是带双引号的连续范围，端口项必须
是十进制整数。只有明确配置为空列表时才匹配全部进程；缺失或无效的 UID 列表仍会
清理相应专用链。

## 内核要求

设备内核必须启用 IPv4/IPv6 netfilter、`owner`、`connbytes`、`NFQUEUE`（通常对应
`xt_owner`、`xt_connbytes`、`xt_NFQUEUE` 模块），并提供 `iptables`/`ip6tables` 的
filter 表和 `NFQUEUE --queue-bypass` 参数。某个地址族缺少能力时，脚本只清理该族
的专用链，不会移除另一族的工作规则，也不会修改 Box、DNS 或通用 filter 链。队列由
custom core 负责读取；未运行时
`--queue-bypass` 允许连接继续通过。

## 实机验证

在已取得 root 的测试设备上（确认设备和网络均为测试环境）执行：

```sh
grep -A24 '^sni_filter:' /data/adb/agh/bin/AdGuardHome.yaml
iptables -t filter -S AGHMOD_SNI4
ip6tables -t filter -S AGHMOD_SNI6
iptables -t filter -C OUTPUT -j AGHMOD_SNI4
ip6tables -t filter -C OUTPUT -j AGHMOD_SNI6
iptables -t filter -L AGHMOD_SNI4 -v -n
```

启用后应看到每个配置 TCP 端口均生成对应规则；配置非空 UID 范围时，规则应包含
`--uid-owner 10000-19999` 或 `--uid-owner 90000-99999`、
`--connbytes 0:20000 --connbytes-dir original`、`NFQUEUE` 和
`--queue-bypass`，并且已具备内核支持的地址族计数器会在测试应用建立 TLS 连接时增加；
若配置 `uids: []`，规则仍应存在并包含 `NFQUEUE`，但不应包含
`-m owner` 或 `--uid-owner`；只有 UID 列表缺失或无效时，相应专用链才会被清理。
若设备缺少 IPv6 NFQUEUE 支持，仅 `AGHMOD_SNI6` 应被清理，`AGHMOD_SNI4` 仍应保持。

验证配置缩小时的收敛：先配置多个 UID 范围、TCP 端口和 QUIC 端口并等待守护循环，
记录四个链的 `-S` 输出；随后从 YAML 删除至少一个 UID 范围及一个 TCP/QUIC 端口，
再等一轮（最多约 60 秒）并重复检查。四条链都应只保留当前 YAML 对应规则，已删除
的 UID/端口组合不应再出现；例如删除 `90000-99999`、TCP `8443` 和 QUIC `8853` 后：

```sh
! iptables -t filter -S AGHMOD_SNI4 | grep -E -- '--uid-owner 90000-99999|--dport 8443'
! ip6tables -t filter -S AGHMOD_SNI6 | grep -E -- '--uid-owner 90000-99999|--dport 8443'
! iptables -t filter -S AGHMOD_QUIC4 | grep -E -- '--uid-owner 90000-99999|--dport 8853'
! ip6tables -t filter -S AGHMOD_QUIC6 | grep -E -- '--uid-owner 90000-99999|--dport 8853'
```

把 `sni_filter.enabled` 改回 `false` 且将 blocking mode 改为非 `strong` 后，
等待守护循环一轮，再确认 `-S AGHMOD_SNI4`/`-S AGHMOD_SNI6` 返回链不存在；
同时确认 Box 链和 DNS 链规则未发生变化。
