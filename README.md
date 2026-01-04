# PF-Web v3-lite

一个轻量级的端口转发管理面板，支持 TCP/UDP 转发、端口段映射以及 IP 白名单管理。
基于 Node.js Express，单文件脚本一键安装，无依赖残留。

## ✨ 特性

- **轻量级**：自动安装 Node.js 环境，极低资源占用。
- **端口映射**：支持 `Listen -> Target` 单端口、批量端口、端口段映射。
- **安全性**：支持 `TARGET_ALLOWLIST` 目标 IP 白名单模式，防止被滥用。
- **Web 面板**：内置精美暗色系 Web 管理界面，支持延迟测速。
- **持久化**：使用 systemd 守护进程，重启自动运行。

## 🚀 一键安装

```bash
bash <(curl -sL [https://raw.githubusercontent.com/你的用户名/pf-web-lite/main/install.sh](https://raw.githubusercontent.com/你的用户名/pf-web-lite/main/install.sh))
