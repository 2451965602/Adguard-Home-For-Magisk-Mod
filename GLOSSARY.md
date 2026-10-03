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
