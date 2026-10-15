# TunBridge Ubuntu Desktop 0.3.0 功能验收说明

制品版本：`0.3.0`

目标系统：Ubuntu Desktop 24.04 LTS / Ubuntu Desktop 26.04 LTS x86_64

## 安装

在制品目录执行：

```sh
sha256sum -c SHA256SUMS
sudo apt install ./TunBridge_0.3.0_amd64.deb
```

安装完成后无需创建或加入 `tunbridge` 用户组，也无需重新登录。可直接从应用菜单启动 TunBridge，
或在终端执行 `tunbridge-desktop`。

## 本版本验收范围

- 与 Windows 版本一致的 UI、导航、主题、语言、托盘和窗口状态；
- 本机 loopback HTTP/SOCKS5 代理发现与临时测试；
- Profile 创建、修改、删除、持久化及 Secret Service 凭据；
- System TUN 的 Start、Status、Stop、Recover 和 App lease 安全退出；
- HTTP/SOCKS5、有认证/无认证上游；
- 实时流量、连接分页、单连接关闭和全部连接关闭；
- website/IP/system diagnostics 与 XDG 开机启动；
- Mihomo 版本查询、digest 校验更新和 service 重启；
- Settings 中固定维护 helper 的 repair/uninstall。

Start 后会创建产品自有的 `tunbridge` TUN，并由 Mihomo 管理相应路由；Stop、退出、lease 超时或
watchdog 故障收敛后应删除这些产品资产。TunBridge 不修改用户或用户组。

## 建议验收路径

1. 启动已有的本机代理客户端，确认其 HTTP 或 SOCKS5 loopback 端口。
2. 在 TunBridge 中发现/测试代理并保存 Profile；需要认证时填写用户名和密码。
3. 点击 Start，确认状态为 Running，并验证浏览器/终端联网。
4. 查看 Home 流量与 Connections，验证刷新、关闭单连接和关闭全部连接。
5. 点击 Stop；再重复 Start 后从托盘退出，确认系统网络恢复。
6. 验证 Settings 中网站/IP/system info、开机启动、core update 查询及 repair。
7. 重启 App，确认 Profile metadata 保留且凭据仍由 Secret Service 提供。

如 controller 异常、Mihomo 异常终止或产品 TUN 消失，watchdog 应将产品会话收敛到停止状态，
不应删除不属于 TunBridge 的 interface、route 或 DNS 配置。上游客户端退出或关闭本地代理时，
TUN 必须保持，流量应失败而不是直连；约 3 秒后状态显示上游不可用（degraded），上游恢复后自动
清除。上游客户端以同一可执行文件路径重启后应自动重新绑定并恢复联网。

## 卸载

优先在 Settings 中选择 Uninstall 并完成系统授权，也可以在退出 TunBridge 后执行：

```sh
sudo apt purge tun-bridge
```

系统 service、socket、engine、manifest 和产品运行状态会被删除。用户级 Profile、Secret Service
凭据、窗口/WebKit 数据按桌面应用数据保留策略保留；如不再需要，可由用户自行删除。

## 反馈信息

请记录 Ubuntu 版本、X11/Wayland、桌面环境、上游协议及认证方式、操作步骤、错误提示和截图。
本包是 Ubuntu Desktop 阶段版本，目前未进行发行签名。
