# Third-party software

The portable package includes the unmodified official Windows amd64 binary of **Xray-core v26.10.31**, published by XTLS.

- Source and corresponding release: https://github.com/XTLS/Xray-core/tree/v26.10.31
- Upstream release: https://github.com/XTLS/Xray-core/releases/tag/v26.10.31
- License: Mozilla Public License 2.0; complete upstream text accompanies the binary in `core/LICENSE`.
- Original upstream archive SHA256: `2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a`.

NCV Desktop does not modify Xray-core. The included package needs no Wintun or geodata files: it uses loopback SOCKS inbounds and explicit candidate routes, without TUN, geoip or geosite rules.

The NCV Desktop UI follows the neutral layout of the existing NCV project; it uses system fonts and no external runtime assets. This software is not affiliated with v2rayN or XTLS.
