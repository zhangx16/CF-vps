# CF VPS 扫描控制台

将原 `scan_dmit_cf_fallback.py` 的 HTTPS 探测封装成可持久化、可恢复的服务器扫描工具。中文网页支持实时进度、历史任务、停止/续扫、网段文件导入、命中/二次确认筛选及 CSV 导出。Python 3.9+ 标准库，无 pip、Node、数据库服务依赖。

仅探测你拥有或获得授权的目标。命中表示响应具有 Cloudflare 特征；即使两个 SNI 均命中，也**不能单独证明目标使用 Reality 或存在回落漏洞**，直连 CF 的地址也可能命中。TLS 验证按原脚本关闭，用于特征探测，不提供服务身份认证。

## 一键部署

Ubuntu 22.04+ / Debian 12+，root、systemd：

```bash
curl -fsSL https://raw.githubusercontent.com/zhangx16/CF-vps/main/install.sh -o /tmp/cf-vps-install.sh && sudo bash /tmp/cf-vps-install.sh
```

安装完成输出用户名 `admin` 和随机密码。配置位于 `/etc/cf-vps.env`（仅 root 可读）；服务使用独立 `cf-vps` 用户，开机启动。

默认监听 `127.0.0.1:8787`。在你的电脑执行：

```bash
ssh -N -L 8787:127.0.0.1:8787 root@你的服务器IP
```

保持 SSH 连接，在电脑浏览器访问 **http://127.0.0.1:8787**，输入安装时显示的账号密码。扫描在服务器执行，关闭网页或 SSH 隧道不影响扫描。

需要直接通过服务器 IP 访问时，首次安装可使用以下命令（仅用于可信网络；公网推荐下方 HTTPS）：

```bash
sudo env CFVPS_BIND=0.0.0.0 bash /tmp/cf-vps-install.sh
```

此时访问 `http://服务器IP:8787`，需在服务器防火墙和云安全组放行该端口。HTTP Basic 登录应通过 HTTPS 或 SSH 隧道使用。

## 使用自己的域名在线访问

将域名 A 记录指向服务器，保留面板监听本机地址，用现有 Nginx / Caddy 反向代理。Caddy 示例（域名正确解析，80/443 可用，自动申请 HTTPS）：

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

## 更新、管理与备份

重新运行安装命令即可更新代码，保留密码、端口、历史任务；更新时停止当前任务，完成后可在面板续扫。可用 `CFVPS_REF=<commit SHA>` 固定安装版本。

```bash
sudo systemctl status cf-vps
sudo journalctl -u cf-vps -n 100 --no-pager
sudo systemctl restart cf-vps
sudo nano /etc/cf-vps.env
# 修改配置后重启生效
sudo systemctl restart cf-vps
```

`CFVPS_PASSWORD` 至少 16 位，安装器生成的密码满足要求。修改后浏览器可能需要重新输入登录信息。修改端口/监听地址请编辑上述配置，更新安装不会覆盖。

备份时先停止服务，复制整个数据目录（含 SQLite WAL），再启动：

```bash
sudo systemctl stop cf-vps
sudo cp -a /var/lib/cf-vps /var/lib/cf-vps-backup-$(date +%Y%m%d-%H%M%S)
sudo systemctl start cf-vps
```

结果历史不会自动清理，需定期留意磁盘空间。移除服务（保留配置和数据）：

```bash
sudo systemctl disable --now cf-vps
sudo rm /etc/systemd/system/cf-vps.service
sudo systemctl daemon-reload
sudo rm -rf /opt/cf-vps
```

## 本地运行与验证

```bash
CFVPS_PASSWORD='替换成至少16位的随机密码' python3 server.py
# 访问 http://127.0.0.1:8787，用户 admin
python3 -m unittest discover -s tests -v
```

部署器会检查 Python 语法及服务启动状态。GitHub Actions 在 Python 3.9 / 3.11 / 3.13 上运行同一组测试。测试使用模拟探测和本机 HTTPS 服务，不扫描外部网段。

原命令行入口仍保留，HTTP 读取逻辑已修正：

```bash
python3 scan_dmit_cf_fallback.py --ip 你的已授权IP --ports 443 --output hits.csv
```

原 CLI 的批处理/CSV 续跑逻辑保留兼容性；固定 worker、SQLite 检查点和完整任务恢复由新的网页控制台提供。不要同时启动两个 `server.py` 实例共享同一数据目录。
