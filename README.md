# DDNS Master
一款基于 Go 语言开发的轻量级、自托管动态域名解析 (DDNS) 管理面板，专为 Cloudflare 用户打造。

🌟 项目简介
DDNS Master 旨在提供一个精致且直观的界面，帮助用户自动化维护域名与动态 IP 的映射关系。无论是家庭宽带的 IPv6 更新，还是 VPS 的公网 IP 变动，它都能确保你的服务始终在线，并通过 Telegram 实时告知变更状态。

✨ 核心特性
极简部署：采用单文件架构，无复杂依赖，即开即用。

现代仪表盘：采用模块化卡片布局，实时监控托管域名数量、同步状态及最近运行时间。

双栈支持：完美支持 IPv4 (A 记录) 与 IPv6 (AAAA 记录) 的自动解析更新。

多源获取 IP：

通过外部 Web API (如 ipify) 获取公网 IP。

直接从系统网卡接口 (Interface) 获取局域网或内网地址。

智能通知：集成 Telegram Bot 消息推送，IP 发生变动时第一时间接收告警。

数据管理：内置账户安全校验，支持一键导出/导入 JSON 配置备份。

极致视觉：精简 UI 设计，去除冗余浮窗，提供响应式的仪表盘配置体验。

🛠️ 技术栈
语言：Go (Golang)。

框架：Gin Web Framework。

数据库：SQLite (通过 GORM 驱动)。

样式：Bootstrap 5 + Bootstrap Icons。

🚀 快速开始
1. 编译运行
确保你的环境中已安装 Go 1.20+。

Bash
# 克隆项目或直接保存 main.go
```
go mod init ddns-master
```
```
go mod tidy
```
```
go run main.go
```
2. 访问面板
打开浏览器访问：http://localhost:8080。

3. 初始化
设置账号：首次打开需设置管理员账号与密码。

配置参数：在“系统配置”中填入你的 Cloudflare API Token。

添加域名：在仪表盘点击“添加域名”，输入你的完整域名并选择 IP 来源即可。

📂 备份与迁移
项目运行后会生成 ddns_panel.db 数据库文件。你可以通过面板内的“导出备份”功能获取配置快照，方便在不同服务器间快速迁移。

注意：本项目目前专注于 Cloudflare 服务商。由于使用了 GORM 与 SQLite，请确保运行环境具备文件写入权限。
