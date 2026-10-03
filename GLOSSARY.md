# AdGuard Home Magisk Module

The Android root-module context that combines AdGuard Home with optional proxy modules while preserving user DNS configuration across upgrades.

## Language

**Custom core**:
The AdguardHome-Mod Linux/arm64 binary shipped by this module; it supplies module-specific behavior beyond upstream AdGuard Home.
_Avoid_: manager app, module script

**SNI filtering**:
Optional blocking of TLS connections by the clear-text Server Name Indication, using the same domain filtering rules as AdGuard Home.
_Avoid_: Mihomo sniffing

**Strong mode**:
The custom-core filtering mode that returns NODATA for blocked DNS names and activates SNI filtering when its external packet rules are available.
_Avoid_: standard DNS blocking

**Legacy configuration migration**:
The upgrade-time preservation of user-owned AdGuard Home settings, rules, filter data, and proxy subscription settings from the installed module.
_Avoid_: copying module scripts or Box-generated configuration

**Policy ECS**:
An EDNS Client Subnet value attached by Mihomo only for the DNS policy that selects it, rather than a global AdGuard Home setting.
_Avoid_: resolver address, proxy exit address

**ECS pass-through**:
AdGuard Home forwarding an ECS option already present in a client DNS request to its upstream resolver without replacing it.
_Avoid_: global custom ECS

**随机 DNS 端口（`random_dns_port`）**：
`config.prop` 中控制明文 DNS 端口是否随机化的开关，默认值为 `yes`。启用时同时更新 AdGuard Home 与由模块管理的 Mihomo DNS 配置；设为 `no` 时保留有效的 `redir_port`，无效或缺失时使用 `5591`，且不改写 Mihomo。
_Avoid_: TLS/DoH 端口随机化

**AGH-managed Mihomo DNS**：
由 AdGuard Home 模块写入并维护的 Mihomo DNS 地址项；只有明文 DNS 端口随机化策略启用时才会更新。TLS 生效时不会写入该项。
_Avoid_: 用户自定义 Mihomo DNS

**TLS runtime-only override**：
当 AdGuard Home 的 TLS 已启用且 `port_https > 0` 时，仅对本次运行临时覆盖 `random_dns_port` 为禁用，并禁止写入 Mihomo；该覆盖不回写 `config.prop`。允许在首次执行时清理旧版受管标记，但不据此重写用户配置。

**固定 DoH 端点**：
TLS/DoH 使用稳定的 HTTPS 端点，不随明文 DNS 端口策略变化；端点稳定性是客户端发现、证书校验和外部配置可持续性的约束。证书、私钥及其他秘密不属于本仓库内容。
