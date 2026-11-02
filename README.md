# CF VPS 扫描控制台

将原 `scan_dmit_cf_fallback.py` 的 HTTPS 探测封装成可持久化、可恢复的服务器扫描工具。中文网页支持实时进度、历史任务、停止/续扫、网段文件导入、命中/二次确认筛选及 CSV 导出。Python 3.9+ 标准库，无 pip、Node、数据库服务依赖。

仅探测你拥有或获得授权的目标。命中表示响应具有 Cloudflare 特征；即使两个 SNI 均命中，也**不能单独证明目标使用 Reality 或存在回落漏洞**，直连 CF 的地址也可能命中。TLS 验证按原脚本关闭，用于特征探测，不提供服务身份认证。

## 一键部署

Ubuntu 22.04+ / Debian 12+，root、systemd：

```bash
curl -fsSL https://raw.githubusercontent.com/zhangx16/CF-vps/main/install.sh -o /tmp/cf-vps-install.sh && sudo bash /tmp/cf-vps-install.sh
```

安装完成输出用户名 `admin` 和随机密码。配置位于 `/etc/cf-vps.env`（仅 root 可读）；服务使用独立 `cf-vps` 用户，开机启动。

默认监听 **`0.0.0.0:8787`**，安装后直接访问 **`http://服务器公网IP:8787`**。输入安装结束时显示的用户名 `admin` 和随机密码。

如果 UFW 已启用，安装器会自动放行面板的 TCP 端口；云安全组、firewalld 或自定义 iptables/nftables 规则需自行放行对应端口。安装器不会启用、重置或关闭系统防火墙。公网长期使用可按下方示例配置 HTTPS。

安装后输入以下命令进入中文管理菜单：

```bash
cf-vps
# 普通用户使用 sudo cf-vps
```

旧版本升级并立即开放公网（保留原密码、端口和数据，自动添加管理命令）：

```bash
curl -fsSL https://raw.githubusercontent.com/zhangx16/CF-vps/main/install.sh -o /tmp/cf-vps-install.sh && sudo env CFVPS_BIND=0.0.0.0 bash /tmp/cf-vps-install.sh
```

已有管理命令时，直接执行 `sudo cf-vps public`。普通升级保留当前监听地址；切换为仅本机访问可执行 `sudo cf-vps private`。首次安装想只监听本机，可设置 `CFVPS_BIND=127.0.0.1`。

## 使用自己的域名在线访问

将域名 A 记录指向服务器，用现有 Nginx / Caddy 反向代理。代理在同一台机器时，可用 `cf-vps private` 让面板仅监听本机。Caddy 示例（域名正确解析，80/443 可用，自动申请 HTTPS）：

```caddyfile
scan.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

随后访问 `https://scan.example.com`，仍需面板账号密码。不要为面板开启跨域访问或绕过认证。

## 面板使用

1. 输入 IPv4 / CIDR，每行一个或逗号分隔，也可导入文本文件。留空使用项目内 `dmit_prefixes.txt` 静态快照，来源于用户原文件，不会自动更新 ASN。
2. 设置端口、并发、超时。默认 `443,8443`、100 并发、4 秒、失败尝试 1 次。失败尝试次数含首次请求，只重试连接/读取失败。
3. 开始后每两秒更新进度、速度、预计剩余时间。命中后自动使用另一 SNI 再确认。
4. 停止后可继续，服务重启前的任务会标记“服务中断”，手动续扫即可。关闭网页不会停止扫描。
5. 下方按命中、二次确认或全部探测筛选，CSV 导出对应筛选结果。全部结果含未命中地址，因此续扫能正确跳过已完成的 IP:端口。

一次只运行一个任务，并发上限 300、端口最多 16 个、单任务最多 200 万个 IP:端口。重叠网段会合并，通常网段排除网络地址与广播地址，`/31`、`/32` 按 Python `hosts()` 规则处理。导入文件上限 64 KB。

HTTP 读写有总超时，响应头/正文分别限制在约 64 KB，支持分段到达和 chunked 正文。固定数量 worker 按需生成目标，不建立全量 IP 列表或目标任务；结果写入 SQLite WAL，最多约 0.5 秒或 50 条提交一次。正常停止保存所有已完成探测；断电可能重测最后未提交的一小批。停止会等待在途请求完成，极端情况下约 `2 × timeout + 0.5` 秒。

## 快捷管理命令

运行 `cf-vps` 打开数字菜单，包含安装、升级、状态、启动、停止、重启、日志、备份、恢复、公网开关、端口设置、密码设置与卸载。所有管理命令需 root 或 sudo。

| 命令 | 功能 |
| --- | --- |
| `cf-vps` | 打开中文管理菜单 |
| `cf-vps install` | 安装 / 重新安装 |
| `cf-vps upgrade` | 自动备份后升级，保留现有设置与扫描记录 |
| `cf-vps status` | 查看状态、监听地址与目录 |
| `cf-vps info` | 查看状态、访问地址及登录密码 |
| `cf-vps start` / `stop` / `restart` | 启动 / 停止 / 重启服务 |
| `cf-vps logs` | 查看最近 100 行日志 |
| `cf-vps public` | 监听所有 IPv4 地址；UFW 已启用时自动放行端口 |
| `cf-vps private` | 改为仅本机监听 |
| `cf-vps port 8888` | 修改端口，保留其他设置 |
| `cf-vps password` | 修改密码；留空生成随机密码 |
| `cf-vps backup` | 在线备份配置和数据库 |
| `cf-vps backups` | 列出所有备份 |
| `cf-vps restore /备份路径.tar.gz` | 先备份当前数据，再恢复指定备份 |
| `cf-vps uninstall` | 卸载服务与程序，保留配置、数据和备份 |
| `cf-vps uninstall --purge` | 卸载并删除配置、扫描数据，保留自动备份 |

菜单的恢复与卸载操作会要求输入 `RESTORE` / `DELETE`，避免误操作。卸载后保留独立的 `cf-vps` 管理命令，方便重新安装。需要移除快捷命令时，再执行 `sudo rm /usr/local/bin/cf-vps`。

新密码至少 16 位。修改监听地址、端口或密码后会重启服务，正在运行的扫描可在网页手动续扫；服务启动失败时会回退原配置。公网入口仍需云安全组放行；换端口后旧防火墙规则不会自动删除。

### 备份与恢复

备份默认保存在 `/var/backups/cf-vps/cf-vps-日期时间.tar.gz`，文件权限 `600`，目录权限 `700`。备份包含登录密码及 SQLite 数据库，使用 SQLite 在线快照接口，不暂停扫描，并包含 WAL 中已提交的数据。

```bash
sudo cf-vps backup
sudo cf-vps backups
sudo cf-vps restore /var/backups/cf-vps/cf-vps-实际文件名.tar.gz
```

恢复前会验证备份并自动备份当前数据；恢复期间停止服务，完成后恢复此前的运行状态。恢复会覆盖任务记录与登录配置，保留当前数据目录位置；恢复出的未完成任务可在网页手动续扫。恢复不回滚程序代码。升级、重新安装、卸载也会在存在配置时自动备份。

所有历史记录与备份都不会自动清理，请定期留意磁盘空间。删除服务与数据后，先执行 `cf-vps install` 再恢复旧备份。

### 版本与配置

重新运行一键安装命令也可升级。可设置 `CFVPS_REF=<commit SHA>` 固定程序版本。升级保留密码、端口、历史记录和监听地址；显式设置 `CFVPS_BIND=0.0.0.0` 时会同步修改已有安装的监听地址。

配置文件为 `/etc/cf-vps.env`，仅 root 可读。也可以直接编辑后执行 `sudo systemctl restart cf-vps`。数据目录为 `/var/lib/cf-vps`，程序目录为 `/opt/cf-vps`。

## 本地运行与验证

```bash
CFVPS_PASSWORD='替换成至少16位的随机密码' python3 server.py
# 默认监听 0.0.0.0:8787，用户 admin；仅本机开发可设置 CFVPS_HOST=127.0.0.1
python3 -m unittest discover -s tests -v
```

部署器会检查 Python 语法及服务启动状态。GitHub Actions 在 Python 3.9 / 3.11 / 3.13 上运行同一组测试。测试使用模拟探测和本机 HTTPS 服务，不扫描外部网段。

原命令行入口仍保留，HTTP 读取逻辑已修正：

```bash
python3 scan_dmit_cf_fallback.py --ip 你的已授权IP --ports 443 --output hits.csv
```

原 CLI 的批处理/CSV 续跑逻辑保留兼容性；固定 worker、SQLite 检查点和完整任务恢复由新的网页控制台提供。不要同时启动两个 `server.py` 实例共享同一数据目录。
