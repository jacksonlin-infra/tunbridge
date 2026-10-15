# TunBridge

[English](README.md)

TunBridge 在你已有的 HTTP(S) 或 SOCKS5 代理前面加一层系统级 TUN，让所有应用（Git、SSH、包管理器、
AI CLI、容器、原生应用）都走这个代理，不需要逐个设置。

```text
应用 → 系统网络栈 → TunBridge TUN → 受控 Mihomo 引擎
                                   ├→ 现有代理客户端的 127.0.0.1 HTTP/SOCKS5
                                   └→ 手工填写的远程 HTTP(S)/SOCKS5 endpoint
```

<p align="center">
  <img src="docs/images/overview.zh-CN.webp" alt="TunBridge 概览：系统 TUN 运行中" width="860">
</p>

更多截图见 [docs/screenshots.md](docs/screenshots.md#中文)。

TunBridge **不**提供代理服务器、订阅或节点，不扫描局域网，也不解密 TLS 流量，只把流量送到你选定的上游。

## 功能

- **发现本机上游**：找到正在运行的代理客户端的本机监听端口，并确认该端口属于哪个进程后才使用。
- **远程上游（实验性）**：支持局域网或公网的 HTTP(S)、SOCKS5 endpoint，凭据存放在系统凭据库（Credential Manager、Secret Service 或钥匙串）。
- **故障时保持阻断**：隧道开启后，只有用户明确操作才会关闭。上游、引擎或界面出故障时，流量保持阻断并通知你，
  不会悄悄改为直连。
- **最小权限**：由一个小的特权服务（Windows 服务、systemd 服务、macOS helper）管理 TUN、路由和 DNS；
  界面以普通用户运行，只能发送固定的几种强类型命令。
- **可观测**：流量、连接、Mihomo 日志、隧道事件和连通性诊断。
- 浅色/深色主题；界面语言：简体中文、繁體中文、日本語、English。

## 平台

| 平台 | 安装包 | 状态 |
| --- | --- | --- |
| Windows 11 x86_64 | NSIS 安装程序 `.exe` | Beta，未做代码签名 |
| Ubuntu 24.04 / 26.04 x86_64 | `.deb` | Beta |
| Omarchy 4 x86_64（基于 Arch） | pacman `.pkg.tar.zst` | Beta |
| macOS 12+ Apple 芯片与 Intel | `.dmg` / `.pkg` | 预览版：ad-hoc 签名，未公证 |

所有平台共用一个版本号、一个 Release。从 [Releases](https://github.com/jacksonlin-infra/tunbridge/releases)
下载对应安装包，并用 `SHA256SUMS` 校验。

安装包目前没有签名，首次打开时 Windows SmartScreen 和 macOS Gatekeeper 会提示。macOS 上请在访达里右键 →
打开一次。

应用内“检查更新”读取同一个 Releases 页面，发现新版本后打开该页面，不会自行安装。

## 工作原理

TunBridge 以受控方式运行 [Mihomo](https://github.com/MetaCubeX/mihomo)。特权服务会：

1. 校验内置引擎的大小和 SHA-256 与锁定值一致；
2. 由强类型 Profile 生成固定结构的 Mihomo 配置（界面不能传入原始 YAML、路径、URL 或进程号）；
3. 让上游自身的连接绕开隧道，避免流量回环；
4. 把所做的每项改动写入 root/SYSTEM 所有的日志，崩溃或重启后可以精确恢复，不靠猜测或按进程名清理。

详见 [docs/architecture.md](docs/architecture.md) 与 [docs/security-model.md](docs/security-model.md)（英文）。

## 从源码构建

需要 Rust（版本见 `rust-toolchain.toml`）、Node.js 24 和 [`just`](https://github.com/casey/just)。

```bash
npm --prefix apps/desktop ci
just fmt-check
just contract-test
just ui-test
just ui-build
```

安装包必须在各自平台上构建，见 [docs/building.md](docs/building.md)。

## 贡献与安全

- 提交 PR 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 安全漏洞请按 [SECURITY.md](SECURITY.md) 私下报告，不要发公开 issue。

## 许可证

TunBridge 以 [GNU General Public License v3.0 或更高版本](LICENSE) 授权。安装包内含以 GPL-3.0 授权的
Mihomo，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

TunBridge 是独立项目，与 Mihomo、Clash 及任何代理服务商无关。

## Star 趋势

<a href="https://www.star-history.com/#jacksonlin-infra/tunbridge&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=jacksonlin-infra/tunbridge&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=jacksonlin-infra/tunbridge&type=Date" />
    <img alt="Star history chart" src="https://api.star-history.com/svg?repos=jacksonlin-infra/tunbridge&type=Date" />
  </picture>
</a>
