# xboard-node

Node backend for Xboard. Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Installer (Linux systemd)

Use the maintained installer and version-pinned local binaries. The installer does not select a release server by default. Replace the placeholders below with your deployment settings.

```bash
# Node mode
sudo bash install.sh --mode node --panel https://panel.example.com --token YOUR_TOKEN \
  --node-id YOUR_NODE_ID --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64

# Machine mode
sudo bash install.sh --mode machine --panel https://panel.example.com --token YOUR_TOKEN \
  --machine-id YOUR_MACHINE_ID --version YOUR_IMMUTABLE_VERSION --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64
```

For arm64, use the matching `*-linux-arm64` binaries. A private asset server may be configured explicitly with `--download-base` or `XBOARD_NODE_DOWNLOAD_BASE`; no release URL is used implicitly.

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token YOUR_TOKEN --node-id YOUR_NODE_ID
xbctl bind add-machine --panel URL --token YOUR_TOKEN --machine-id YOUR_MACHINE_ID
xbctl bind remove-node --panel URL --node-id YOUR_NODE_ID
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

## Extensions

- Automatic FlowScope egress IPv4 (no collector required): [中文使用、升级和验证说明](FLOWSCOPE-IPV4.md)

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## Dependency maintenance and recovery

- [中文恢复维护指南](DEPENDENCY-RECOVERY.md)
- [中文依赖保护设计](DEPENDENCY-STRATEGY.md)
- [完整风险清单](DEPENDENCY-AUDIT.md)
- [功能验证与未验证范围](DEPENDENCY-TEST-REPORT.md)

Normal Makefile builds require the verified selective Module Proxy snapshot. See the recovery guide for local archive restoration; no dependency proxy service is required on deployed VPS hosts.

## License

MPL-2.0.
