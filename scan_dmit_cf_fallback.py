#!/usr/bin/env python3
"""
扫描 DMIT 段，探测 Reality 回落到 Cloudflare 的节点。

原理（只做一次普通 HTTPS 请求，不尝试 Reality 私钥/ShortID）：
  未认证的 Reality 连接会被服务端透明回落（fallback）到 dest。
  如果 dest 是 CF Anycast IP/域名，继续完成 TLS 握手后，
  对 CF 域名发 GET /cdn-cgi/trace，就会拿到 CF 特征头：
    server: cloudflare / cf-ray: / 响应体含 colo=、fl=
  正常网站 / dest 不是 CF 的 Reality 节点不会返回这些特征。

用法（Debian，Python3 标准库即可，无需 pip）：
  # 1) 只测一个 IP（先用它验证脚本逻辑是否正常）
  python3 scan_dmit_cf_fallback.py --ip 1.1.1.1

  # 2) 测一个 C 段
  python3 scan_dmit_cf_fallback.py --cidr 154.17.0.0/24

  # 3) 测 DMIT 全部 ASN 段：AS906（主）+ AS132110 + AS32519
  #    先试 bgpview，失败再试 RIPEstat，都失败才用内置常见段兜底
  #    小内存机器务必用 --concurrency 100 --batch-size 2000（旧版一次建几万个
  #    任务会被 OOM killer 直接 Killed）
  python3 scan_dmit_cf_fallback.py --asn 906,132110,32519 \
      --ports 443,8443 --concurrency 100 --batch-size 2000 --timeout 4 \
      --output hits.csv

  # 3b) 服务器 DNS 实在拉不到 ASN 时：先在能解析的机器上拉好前缀文件再传上去
  #     curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS906"
  #     （另两个 ASN 同理，合并成一个 prefixes.txt，每行一个 CIDR）
  #     python3 scan_dmit_cf_fallback.py --prefix-file prefixes.txt --ports 443,8443

  # 4) 断点续跑（跳过 hits.csv / results.csv 里已测过的 ip:port）
  python3 scan_dmit_cf_fallback.py --asn 906 --resume --output hits.csv

注意：
  * 扫描总量约 8~9 万 IP x 2 端口，并发别开太高，避免触发机房 IDS/限速。
  * 命中只代表“该 IP:port 会把请求回落到 CF”，不代表你有权使用它。
    非本人/未授权的节点不要拿去当反代用：会偷占他人带宽、随时失效，
    且代理方能看到 SNI/目标域名等元数据，安全性不可控。
  * 自己搭 Reality 时 dest 千万别填 CF，见文件末尾示例。
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import re
import ssl
import sys
import time
import urllib.request
from pathlib import Path

PRIMARY_SNI = "www.cloudflare.com"
VERIFY_SNI = "one.one.one.one"  # 也是 CF 域名，用于二次确认是“通用 CF 回落”而非单个站点
TRACE_PATH = "/cdn-cgi/trace"

# bgpview 拉不到时兜底：DMIT 较常见的段（不全，仅作示例/兜底，以 ASN 拉取为准）
FALLBACK_PREFIXES = [
    "154.12.180.0/24", "154.12.181.0/24", "154.12.182.0/24",
    "154.12.183.0/24", "154.12.184.0/24", "154.12.185.0/24",
    "154.12.186.0/24", "154.12.187.0/24",
    "154.17.0.0/19", "154.17.6.0/24", "154.17.225.0/24", "154.17.230.0/24",
    "45.88.192.0/22", "45.88.194.0/24", "45.88.195.0/24",
    "103.117.100.0/23", "103.117.102.0/23", "103.135.248.0/22",
    "193.110.201.0/24", "64.186.224.0/20", "64.186.240.0/20",
    "69.63.201.0/24", "69.63.213.0/24", "69.63.215.0/24",
]


def _fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "dmit-cf-scan/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)


def fetch_asn_prefixes(asns):
    """拉取 ASN 的 IPv4 前缀：先 bgpview，失败再试 RIPEstat，都失败返回 []。"""
    prefixes = []
    for asn in asns:
        got = []
        # 1) bgpview
        try:
            data = _fetch_json(f"https://api.bgpview.io/asn/{asn}/prefixes")["data"]
            got = [item["prefix"] for item in data.get("ipv4_prefixes", [])]
        except Exception as e:  # noqa: BLE001
            print(f"[!] AS{asn} bgpview 拉取失败（{e}），改试 RIPEstat", file=sys.stderr)
        # 2) RIPEstat：announced-prefixes，prefix 字段里 IPv4 含 '.'
        if not got:
            try:
                data = _fetch_json(
                    f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
                )["data"]
                got = [p["prefix"] for p in data.get("prefixes", []) if "." in p.get("prefix", "")]
            except Exception as e:  # noqa: BLE001
                print(f"[!] AS{asn} RIPEstat 拉取也失败（{e}）", file=sys.stderr)
        if got:
            print(f"[+] AS{asn}: {len(got)} 个 IPv4 前缀", file=sys.stderr)
            prefixes.extend(got)
    return prefixes


def expand_prefixes(prefix_strs):
    """去重、合并重叠段，展开为 IP 列表。"""
    nets = []
    for p in prefix_strs:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError as e:
            print(f"[!] 跳过非法段 {p}: {e}", file=sys.stderr)
            continue
        if net.version != 4 or net.is_private or net.is_reserved or net.is_loopback:
            continue
        nets.append(net)
    nets = list(ipaddress.collapse_addresses(nets))
    ips = []
    for net in nets:
        if net.prefixlen == 32:
            ips.append(str(net.network_address))
        else:
            ips.extend(str(ip) for ip in net.hosts())
    # 去重并保持顺序
    return list(dict.fromkeys(ips))


def parse_trace_body(text):
    """解析 /cdn-cgi/trace 响应体：fl= / colo= / loc= 这种 k=v 行。"""
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.strip() in ("fl", "colo", "loc", "h", "ip"):
                out[k.strip()] = v.strip()
    return out


_SSL_CTX = None


def _ssl_ctx():
    """全局复用一个 SSL 上下文：旧版每次探测都新建上下文，又慢又占内存。"""
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode = ssl.CERT_NONE
        # 强制 HTTP/1.1，避免服务端/代理对 h2 的处理差异
        _SSL_CTX.set_alpn_protocols(["http/1.1"])
    return _SSL_CTX


async def probe_once(ip, port, sni, timeout):
    """Read a bounded complete HTTP response under a single deadline."""
    writer = None
    t0 = time.monotonic()

    async def exchange():
        nonlocal writer
        reader, writer = await asyncio.open_connection(
            ip, port, ssl=_ssl_ctx(), server_hostname=sni, limit=65536)
        writer.write((f"GET {TRACE_PATH} HTTP/1.1\r\nHost: {sni}\r\n"
                      "User-Agent: dmit-cf-scan/2.0\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n").encode())
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        headers = {}
        for line in head.decode('latin1').split('\r\n')[1:]:
            key, sep, value = line.partition(':')
            if sep:
                headers[key.lower()] = value.strip()
        body = bytearray()
        if 'chunked' in headers.get('transfer-encoding', '').lower():
            for _ in range(4096):
                size = int((await reader.readuntil(b'\r\n')).split(b';')[0], 16)
                if size == 0:
                    break
                if size < 0 or len(body) + size > 65536:
                    raise ValueError('Response too large')
                body.extend(await reader.readexactly(size))
                if await reader.readexactly(2) != b'\r\n':
                    raise ValueError('Invalid chunk')
            else:
                raise ValueError('Too many chunks')
        elif 'content-length' in headers:
            size = int(headers['content-length'])
            if not 0 <= size <= 65536:
                raise ValueError('Response too large')
            body.extend(await reader.readexactly(size))
        else:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > 65536:
                    raise ValueError('Response too large')
        return head.decode('latin1'), headers, body.decode('utf-8', 'ignore')

    try:
        head, headers, body = await asyncio.wait_for(exchange(), timeout=timeout)
        server = headers.get('server', '')
        ray = headers.get('cf-ray', '')
        trace = parse_trace_body(body)
        is_cf = ('cloudflare' in server.lower() or bool(ray)
                 or ('colo' in trace and 'fl' in trace))
        return is_cf, server, ray, trace, head, '', int((time.monotonic() - t0) * 1000)
    except Exception as exc:
        return False, '', '', {}, '', type(exc).__name__, ''
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.25)
            except Exception:
                pass


async def probe(ip, port, timeout, sem):
    """主探测 + 命中后二次验证。返回 dict 或 None（未开放/非 CF 时只在 --all 时记录）。"""
    async with sem:
        is_cf, server, cf_ray, trace, _head, err, latency = await probe_once(
            ip, port, PRIMARY_SNI, timeout
        )
        if not is_cf:
            # 区分“端口开了但不是 CF”和“根本连不上”：err 为空说明握手+HTTP 都通了
            status = "open_not_cf" if err == "" else "closed_or_error"
            return {
                "ip": ip, "port": port, "status": status,
                "server": server, "cf_ray": cf_ray, "colo": trace.get("colo", ""),
                "loc": trace.get("loc", ""), "verified": "", "latency_ms": latency if err == "" else "",
                "err": err,
            }
        # 二次验证：换一个 CF 域名还命中，才算“通用 CF 回落”
        is_cf2, _s2, cf_ray2, trace2, _h2, _e2, _l2 = await probe_once(
            ip, port, VERIFY_SNI, timeout
        )
        return {
            "ip": ip, "port": port, "status": "hit",
            "server": server, "cf_ray": cf_ray, "colo": trace.get("colo", ""),
            "loc": trace.get("loc", ""), "verified": "1" if is_cf2 else "0",
            "latency_ms": latency, "err": "",
            "verify_cf_ray": cf_ray2, "verify_colo": trace2.get("colo", ""),
        }


def load_done(path):
    done = set()
    if path and Path(path).exists():
        try:
            with open(path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if row.get("ip") and row.get("port"):
                        done.add((row["ip"], int(row["port"])))
        except Exception:  # noqa: BLE001
            pass
    return done


async def main_async(args):
    # ---- 目标 IP 来源：--ip > --cidr > --prefix-file > --asn ----
    ips = []
    if args.ip:
        ips = [args.ip]
    elif args.cidr:
        ips = expand_prefixes([c.strip() for c in args.cidr.split(",") if c.strip()])
    elif args.prefix_file:
        with open(args.prefix_file, encoding="utf-8") as f:
            prefixes = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"[+] 前缀文件 {args.prefix_file}：{len(prefixes)} 个段", file=sys.stderr)
        ips = expand_prefixes(prefixes)
    else:
        asns = [a.strip() for a in args.asn.split(",") if a.strip()]
        prefixes = fetch_asn_prefixes(asns)
        if not prefixes:
            print("[!] ASN 拉取全失败，使用内置兜底段（不全，仅约 2.3 万 IP）", file=sys.stderr)
            print("[!] 想跑全量请用 --prefix-file，或先修 DNS（见 README 提示）", file=sys.stderr)
            prefixes = FALLBACK_PREFIXES
        ips = expand_prefixes(prefixes)

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    targets = [(ip, port) for ip in ips for port in ports]

    done = set()
    if args.resume:
        done |= load_done(args.output)
        done |= load_done(args.all)
        targets = [t for t in targets if t not in done]
        print(f"[+] 续跑：跳过已测 {len(done)} 个，剩余 {len(targets)} 个", file=sys.stderr)

    print(f"[+] 目标：{len(ips)} 个 IP x {len(ports)} 端口 = {len(targets)} 次探测，"
          f"并发 {args.concurrency}，超时 {args.timeout}s", file=sys.stderr)

    sem = asyncio.Semaphore(args.concurrency)
    hit_fields = ["ip", "port", "status", "server", "cf_ray", "colo", "loc",
                  "verified", "latency_ms", "verify_cf_ray", "verify_colo", "err"]
    hit_file = open(args.output, "a", newline="", encoding="utf-8")
    hit_writer = csv.DictWriter(hit_file, fieldnames=hit_fields)
    if hit_file.tell() == 0:
        hit_writer.writeheader()

    all_writer = None
    all_file = None
    if args.all:
        all_file = open(args.all, "a", newline="", encoding="utf-8")
        all_writer = csv.DictWriter(all_file, fieldnames=hit_fields)
        if all_file.tell() == 0:
            all_writer.writeheader()

    # 分批跑：旧版一次把几万个任务全建出来，小内存机器会被 OOM killer Killed。
    # 每批只建 batch_size 个任务，跑完释放再建下一批。
    n_done = 0
    n_hit = 0
    t_start = time.time()
    try:
        for batch_start in range(0, len(targets), args.batch_size):
            batch = targets[batch_start:batch_start + args.batch_size]
            tasks = [asyncio.ensure_future(probe(ip, port, args.timeout, sem)) for ip, port in batch]
            for coro in asyncio.as_completed(tasks):
                res = await coro
                n_done += 1
                if all_writer:
                    all_writer.writerow({k: res.get(k, "") for k in hit_fields})
                if res["status"] == "hit":
                    n_hit += 1
                    hit_writer.writerow({k: res.get(k, "") for k in hit_fields})
                    hit_file.flush()
                    print(f"[HIT] {res['ip']}:{res['port']} server={res['server']} "
                          f"cf-ray={res['cf_ray']} colo={res['colo']} loc={res['loc']} "
                          f"verified={res['verified']} {res['latency_ms']}ms", flush=True)
                if n_done % 1000 == 0:
                    el = time.time() - t_start
                    print(f"[...] {n_done}/{len(targets)} 命中 {n_hit} 用时 {el:.0f}s", file=sys.stderr)
            if all_file:
                all_file.flush()
            print(f"[...] 批次完成 {n_done}/{len(targets)} 命中 {n_hit}", file=sys.stderr)
    finally:
        hit_file.close()
        if all_file:
            all_file.close()
    print(f"[+] 完成：{n_done} 次探测，命中 {n_hit} 个，见 {args.output}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="扫描 DMIT 段中 Reality 回落到 CF 的节点")
    ap.add_argument("--ip", help="只测单个 IP，如 154.17.1.2")
    ap.add_argument("--cidr", help="测指定段，逗号分隔，如 154.17.0.0/24,154.12.180.0/24")
    ap.add_argument("--asn", default="906,132110,32519",
                    help="ASN，逗号分隔（默认 DMIT: 906,132110,32519）")
    ap.add_argument("--prefix-file", default="",
                    help="前缀文件，每行一个 CIDR，优先于 --asn（服务器 DNS 拉不到 ASN 时用）")
    ap.add_argument("--ports", default="443,8443", help="端口，逗号分隔（默认 443,8443）")
    ap.add_argument("--concurrency", type=int, default=100, help="并发数（默认 100，小内存机器别超 100）")
    ap.add_argument("--batch-size", type=int, default=2000, help="每批任务数（默认 2000，防 OOM）")
    ap.add_argument("--timeout", type=float, default=4, help="单次超时秒数（默认 4）")
    ap.add_argument("--output", default="hits.csv", help="命中结果 CSV（默认 hits.csv）")
    ap.add_argument("--all", default="", help="可选：记录全部探测结果的 CSV（含 open_not_cf）")
    ap.add_argument("--resume", action="store_true", help="跳过 output/all 里已有的 ip:port")
    args = ap.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()

# ---------------- 自己搭 Reality 时，dest 应该怎么写 ----------------
# 错误示范（会把你的 VPS 变成公开 CF 反代，人人可用你的带宽）：
#   "dest": "104.21.0.1:443"          # CF Anycast IP
#   "dest": "www.cloudflare.com:443"  # 任何解析到 CF 的域名
#
# 正确示范（Xray / sing-box 通用思路）：
#   "dest": "www.microsoft.com:443"     # 或某大学官网:443 等真实目标站
#   "serverNames": ["www.microsoft.com"]  # 必须和 dest 证书的域名一致
#   # dest 站点本身要有真实内容、能正常回源，这样未认证流量回落过去
#   # 看起来就是一次普通访问，不会暴露代理，也不会变成公开反代。
# -------------------------------------------------------------------
