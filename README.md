# CF VPS 扫描控制台

将原 `scan_dmit_cf_fallback.py` 的 HTTPS 探测封装成可持久化、可恢复的服务器扫描工具。中文网页支持实时进度、停止/续扫、证据分级、地区与机房筛选、请求耗时排序、点击复制 IP、历史复测与对比、任务删除及 CSV 导出。界面基于 shadcn/ui dashboard-01，使用 ui-design-iteration 完成参考设计、草稿和浏览器审查。Python 3.9+ 标准库，无 pip、Node、数据库服务依赖。

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

域名 A 记录指向服务器、80/443 可访问后，使用管理命令自动配置 Nginx 与 Let's Encrypt：

```bash
sudo cf-vps domain scan.example.com
```

命令会申请证书、配置 HTTP 到 HTTPS 跳转、添加证书续期后的 Nginx 重载钩子，并让后端仅监听 `127.0.0.1`。Nginx 设置真实客户端地址，面板仅在本机代理连接且 `CFVPS_TRUST_PROXY=1` 时信任它。已存在的非 CF VPS 站点配置不会被覆盖。菜单中也有“配置域名与 HTTPS”。

也可自行使用 Nginx / Caddy 反向代理。Caddy 示例：

```caddyfile
scan.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

随后访问 `https://scan.example.com`，仍需面板账号密码。不要为面板开启跨域访问或绕过认证。

## 面板使用

点击“新建扫描”打开配置弹窗。输入公网 IPv4 / CIDR（每行一个或逗号分隔），或导入不超过 64 KB 的文本；留空使用 `dmit_prefixes.txt` 静态快照。默认端口 `443,8443`、100 并发、4 秒单次总超时、最多尝试 2 次、每秒最多 100 个 HTTPS 尝试。第二域名验证和重试共用同一请求速率限制；连接拒绝不重复尝试，其他请求错误采用短暂退避重试。

一次只运行一个任务，并发上限 300、请求速率上限 1000/秒、最多 16 个端口、单任务最多 200 万个 IP:端口。仅扫描你拥有或获得授权的目标。

### 证据与耗时

| 等级 | 判定 |
| --- | --- |
| 疑似命中 | CF 响应头或弱 Trace 特征 |
| Trace 有效 | HTTP 200，IP/机房/地区/特征字段有效，返回域名与本次 SNI 一致 |
| 双域名确认 | 两个不同 SNI 都通过有效 Trace 检查 |
| 旧版结果 | 保留原判定，不当作新版严格确认；可复测 |

二次验证超时显示“验证失败 · 可复测”，与成功响应但未通过确认区分。连接拒绝、连接超时、TLS 超时/失败、HTTP 超时/错误分别记录。

“请求耗时”包含 TCP、TLS 和 HTTP 读取，不是 ping 延迟；停留在耗时上可查看连接、握手与首字节时间（首字节从请求开始计时）。响应头和正文各限约 64 KB，支持分段和 chunked 响应。

### 地区筛选、排序与复制

- 按 **CF 出口地区**分类，按响应 CF 机房筛选，可与证据等级、IP 前缀/端口搜索组合。
- 排序选择“请求耗时：低 → 高 / 高 → 低”，也可直接点击表头“请求耗时”切换。
- **点击任意 IP:端口复制纯 IP**，成功后显示提示；HTTPS 使用系统剪贴板接口。
- 导出 CSV 遵循当前证据、地区、机房与搜索筛选；导出顺序按记录写入顺序，不随网页排序改变。

CF 出口地区来自 Trace `loc`，响应机房来自 `colo`，均不能代表目标 VPS 的实际物理位置。没有这些字段的结果归入未知地区。旧版耗时兼容导出到 request_ms。

### 复测、历史和任务管理

可复测选中的结果（最多 200 个），或复测该任务全部命中；复测产生独立任务，不覆盖原记录。显示首次命中、最近双域名确认与历次命中率。命中率是保存的观测中命中次数/总观测次数，不能代替长期可用性承诺；旧版记录缺少准确观测时间，不补造历史数据。

历史对比显示两个任务的新增、本次未命中、持续命中数量，并展示最多 200 个端点。含未完成任务时明确标记对比尚不完整。删除任务也会删除相应的结果及观测历史；正在运行的任务及其复测来源不能删除。

进度每两秒刷新，关闭网页不影响扫描。停止、重启、升级后的未完成任务可在网页继续，已保存的未命中目标同样会跳过。

### 持久化与访问控制

固定数量 worker 按需生成目标，不构建全量任务列表。SQLite WAL 每 0.5 秒独立定时提交，或满 50 条提前提交；正常停止保存全部已完成记录，异常断电可能重测未提交的小批次。数据库连接使用后显式关闭；结果页面使用游标分页。重叠网段合并，通常排除网络/广播地址，`/31`、`/32` 按 Python hosts() 规则。

面板最多同时处理 64 个 HTTP 连接，连接有读取超时。每客户端一分钟内 10 次带凭据的错误登录会暂时限流；浏览器首次无凭据的登录挑战不计为失败。

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
| `cf-vps domain scan.example.com` | 配置域名与 HTTPS，后端仅本机监听 |
| `cf-vps rollback` | 回滚上一程序版本及其升级前数据快照 |
| `cf-vps retention 10` | 设置自动备份保留数量，默认 10 |
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

扫描历史需手动删除；备份默认保留最新 10 份，可用 retention 调整。升级回滚依赖的快照额外保留，请定期留意磁盘空间。删除服务与数据后，先执行 `cf-vps install` 再恢复旧备份。

### 程序版本与回滚

程序安装在 `/opt/cf-vps-releases/` 下的独立版本目录，`/opt/cf-vps` 指向当前版本，`/opt/cf-vps-previous` 指向升级前版本。升级先停止服务并保存一致性快照，再切换程序；健康检查失败会尝试恢复旧程序、服务配置和数据快照。初次安装没有上一版本可恢复。

```bash
sudo cf-vps rollback
# 输入 ROLLBACK 确认；先自动备份当前数据，再恢复上一版本代码与升级前数据
```

回滚会回到升级前的数据库与配置状态，因此升级后产生的记录需从回滚前自动备份中另行恢复。支持回滚一次，完成后下一次升级会重新建立回滚点。普通 backup/restore 只恢复数据及配置，不改变代码。卸载移除程序版本目录，保留管理命令及自动备份；域名证书和 Nginx 配置单独保留。

### 配置

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

界面设计依据与审查记录见 [design-contract.md](design-contract.md)，第三方许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

原 CLI 的批处理/CSV 续跑逻辑保留兼容性；固定 worker、SQLite 检查点和完整任务恢复由新的网页控制台提供。不要同时启动两个 `server.py` 实例共享同一数据目录。
