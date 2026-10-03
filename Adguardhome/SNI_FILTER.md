# SNI 过滤

模块脚本只维护 `AGHMOD_SNI4` 和 `AGHMOD_SNI6` 两个 `filter/OUTPUT` 专用链。
默认不启用；custom core 的 YAML 中 `sni_filter.enabled: true`，或
`filtering.blocking_mode: strong` 时才会安装。UID 范围和端口的**模块规则源**是
`scripts/config.prop` 中的 `sni_uid_range` / `sni_ports`；YAML 的
`sni_filter.uids` / `sni_filter.ports` 是 custom core 的描述性兼容字段，不是
iptables 脚本的运行时规则源，且默认值应与 `config.prop` 保持一致。NFQUEUE
编号始终从 YAML 的 `sni_filter.queue_num` 读取。

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
grep -A5 '^sni_filter:' /data/adb/agh/bin/AdGuardHome.yaml
iptables -t filter -S AGHMOD_SNI4
ip6tables -t filter -S AGHMOD_SNI6
iptables -t filter -C OUTPUT -j AGHMOD_SNI4
ip6tables -t filter -C OUTPUT -j AGHMOD_SNI6
iptables -t filter -L AGHMOD_SNI4 -v -n
```

启用后应看到每个配置端口均带有 `--uid-owner 10000-19999`、
`--connbytes 0:20000 --connbytes-dir original`、`NFQUEUE` 和
`--queue-bypass`，并且已具备内核支持的地址族计数器会在测试应用建立 TLS 连接时增加；
若设备缺少 IPv6 NFQUEUE 支持，仅 `AGHMOD_SNI6` 应被清理，`AGHMOD_SNI4` 仍应保持。
把 `sni_filter.enabled` 改回 `false` 且将 blocking mode 改为非 `strong` 后，
等待守护循环一轮，再确认 `-S AGHMOD_SNI4`/`-S AGHMOD_SNI6` 返回链不存在；
同时确认 Box 链和 DNS 链规则未发生变化。
