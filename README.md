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

Use the privately maintained installer and version-pinned local binaries. The installer does not select a release server by default.

```bash
# Node mode
sudo bash install.sh --mode node --panel https://panel.example.com --token TOKEN \
  --node-id 1 --version v1.13-orphan.1 --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64

# Machine mode
sudo bash install.sh --mode machine --panel https://panel.example.com --token TOKEN \
  --machine-id 1 --version v1.13-orphan.1 --binary ./xboard-node-linux-amd64 \
  --xbctl-binary ./xbctl-linux-amd64
```

For arm64, use the matching `*-linux-arm64` binaries. A private asset server may be configured explicitly with `--download-base` or `XBOARD_NODE_DOWNLOAD_BASE`; no release URL is used implicitly.

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
