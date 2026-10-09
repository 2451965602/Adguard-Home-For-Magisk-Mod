# AdGuard Home Magisk Module

The Android root-module context that combines AdGuard Home with optional proxy modules. It does not manage proxy configuration files or subscriptions.

## Language

**Custom core**:
The AdguardHome-Mod Linux/arm64 binary shipped by this module; it supplies module-specific behavior beyond upstream AdGuard Home.
_Avoid_: manager app, module script

**SNI filtering**:
Optional blocking of TLS connections by the clear-text Server Name Indication, using the same domain filtering rules as AdGuard Home.
_Avoid_: Mihomo sniffing

**QUIC-to-TCP fallback**:
An optional policy that prevents selected QUIC connections so clients can retry over TLS/TCP, where SNI filtering can apply.
_Avoid_: native QUIC inspection

**Strong mode**:
The custom-core filtering mode that returns NODATA for blocked DNS names and activates SNI filtering when its external packet rules are available.
_Avoid_: standard DNS blocking

**Legacy configuration migration**:
The upgrade-time preservation of user-owned AdGuard Home settings, rules, and filter data from the installed module.
_Avoid_: copying module scripts or Box-generated configuration

**Policy ECS**:
An EDNS Client Subnet value attached by Mihomo only for the DNS policy that selects it, rather than a global AdGuard Home setting.
_Avoid_: resolver address, proxy exit address

**ECS pass-through**:
AdGuard Home forwarding an ECS option already present in a client DNS request to its upstream resolver without replacing it.
_Avoid_: global custom ECS

**固定 DNS 重定向端口**：
模块始终从 `config.prop` 读取并验证 `redir_port`，无效或缺失时使用 `5591`。服务启动时只同步 AdGuard Home 的 DNS 端口，不随机化或回写配置，也不改动 HTTP/HTTPS 端口。
_Avoid_: 随机 DNS/HTTP 端口

**代理配置管理**：
模块不读取订阅链接、不改写代理 YAML，也不负责同步代理 DNS 配置；代理模块自身的配置由用户管理。
_Avoid_: 模块托管的代理配置

**固定 DoH 端点**：
TLS/DoH 使用稳定的 HTTPS 端点，不随明文 DNS 端口策略变化；端点稳定性是客户端发现、证书校验和外部配置可持续性的约束。证书、私钥及其他秘密不属于本仓库内容。
