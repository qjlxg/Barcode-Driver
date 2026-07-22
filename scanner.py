import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import datetime
import re
from zoneinfo import ZoneInfo
from tqdm import tqdm

# ==========================
# 配置（已合并去重 + 优化）
# ==========================

# 最高优先级特征（命中即判定有效，包含高价值 Python/BaseHTTP 及订阅标识）
HIGH_PRIORITY_SIGNS = [s.lower() for s in [
    "subscription-userinfo", 
    "profile-update-interval",
    "v2rayn-sub",
    "content-disposition",
    "basehttp/0.6 python",
    "simplehttp/0.6 python",
    "clash-party.yaml"
]]

# 普通特征
NORMAL_SIGNS = [s.lower() for s in [
    "proxies:", "proxy-groups:", "proxy-provider:", "proxy-providers:",
    "rules:", "mixed-port:", "allow-lan:", "mode:",
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://",
    "uuid:", "password:", "server:", "port:", 
    "outbounds:", "inbounds:", "servers:", "reality:",
    "[proxy]", "[server]", "policy-group", "proxy-group",
    "clash", "sing-box", "mihomo", "nekobox", "nekoray",
    "type: vmess", "type: vless", "type: trojan", 
    "type: shadowsocks", "type: hysteria", "type: hysteria2",
    "server_name:", "skip-cert-verify:", "tls:", "network:", "flow:", "cipher:"
]]

# 目标端口（完整版）
TARGET_PORTS = [
    80, 443,
    2052, 2053, 2082, 2083, 2087, 2095, 2096,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8088, 8089,
    8443, 8444, 8888, 8889, 8899,
    1333, 1999, 2222, 3002, 3333, 4444, 5555,
    6001, 6666, 7777, 8011, 8787, 9050,
    9981, 9999, 10110, 12202, 18080,
    19999, 54321, 60001, 60002,
    21, 22, 53, 3000, 5000, 7000, 7001, 8000, 8001, 8880,
    9090, 9443, 10000, 10086, 1080, 1081, 1180, 1194,
    12345, 2000, 2020, 2021, 2022, 2077, 2080, 2081,
    3001, 3128, 4000, 5001, 7070, 8090, 8181, 8282,
    9000, 9001, 9500, 10001, 10443, 11223, 13000, 15000,
    20000, 2375, 2376
]

# Web路径（完整版）
PATHS = [
    "", "/",
    "/sub", "/subscribe", "/subscription", "/link", "/s/",
    "/download", "/download/sub", "/download/config",
    "/get", "/getsub", "/getSub",
    "/api/sub", "/api/subscribe", "/api/v1/client/subscribe",
    "/api/v1/user/subscribe", "/api/v1/subscribe",
    "/.api/user/subscribe", "/api/client/subscribe",
    "/client/subscribe", "/user/subscribe",
    "/config.yaml", "/sub.yaml", "/clash.yaml", "/clash.yml",
    "/config.yml", "/profile.yaml", "/profile.yml",
    "/clash", "/clash/config", "/clash/proxies",
    "/v2ray", "/vmess", "/ss", "/trojan", "/hysteria", "/hy2",
    "/sub2", "/sub3", "/subs", "/links", "/nodes", "/node",
    "/all", "/full", "/base64", "/b64", "/yaml", "/yml", "/json", "/txt",
    "/proxies", "/getconfig",
    "/sub?target=clash", "/sub?target=v2ray", "/sub?target=singbox",
    "/clash?type=clash", "/sub?format=clash"
]

WORKER_COUNT = 150
stats = {"req": 0, "saved": 0}
history_data = {}

def normalize_url(url):
    return url.rstrip("/")

def load_existing_results():
    if os.path.exists("scan_results.csv"):
        with open("scan_results.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) >= 6:
                    history_data[normalize_url(row[1])] = row

async def save_result(url, text, host, port, pbar):
    """保存结果到历史记录和文件"""
    content_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
    now_str = datetime.datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    
    norm_url = normalize_url(url)
    os.makedirs("results/hash", exist_ok=True)
    
    file_suffix = hashlib.md5(norm_url.encode()).hexdigest()[:6]
    filename = f"results/hash/{content_hash}_{file_suffix}.txt"
    
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(text)
    
    if norm_url not in history_data:
        row = [content_hash, norm_url, f"{host}:{port}", now_str, 0, content_hash]
    else:
        old_row = history_data[norm_url]
        if old_row[0] != content_hash:
            pbar.write(f"[*] 内容已更新: {url}")
            row = [content_hash, norm_url, f"{host}:{port}", now_str, int(old_row[4]) + 1, old_row[0]]
        else:
            old_row[3] = now_str
            row = old_row
    
    history_data[norm_url] = row

async def scan(session, host, port, path, pbar):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            async with session.get(
                url, 
                timeout=5, 
                ssl=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            ) as resp:
                
                stats["req"] += 1
                if resp.status != 200:
                    continue

                header_text = str(resp.headers).lower()

                # 一级：确定性特征（直接保存）
                if any(s in header_text for s in HIGH_PRIORITY_SIGNS) or \
                   re.search(r'subscription-userinfo|profile-update-interval|v2rayn-sub|content-disposition', header_text):
                    
                    text = await resp.text(errors="ignore")
                    stats["saved"] += 1
                    pbar.write(f"[+] 高优先级发现: {url}")
                    await save_result(url, text, host, port, pbar)
                    pbar.update(1)
                    return True

                # 二级：正文结构判断与网页拦截
                text = await resp.text(errors="ignore")
                lower_text = text.lower()

                # 如果页面返回的内容含有 <html 标签，且不包含节点协议，直接拦截丢弃
                if "<html" in lower_text and not any(proto in lower_text for proto in ["vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://", "rules:","allow-lan: false","proxies:"]):
                    continue

                score = 0
                if "proxies:" in lower_text:
                    score += 3
                if "proxy-groups:" in lower_text:
                    score += 5
                if "uuid:" in lower_text:
                    score += 2
                if any(p in lower_text for p in ["hysteria2://", "vless://", "vmess://", "trojan://", "tuic://"]):
                    score += 5

                if score >= 5 or any(s in lower_text for s in NORMAL_SIGNS):
                    stats["saved"] += 1
                    pbar.write(f"[+] 发现节点: {url}")
                    await save_result(url, text, host, port, pbar)
                    pbar.update(1)
                    return True

        except Exception:
            continue
    
    pbar.update(1)
    return False

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    load_existing_results()
    
    with open(args.file, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    # 提取所有唯一的目标主机/IP
    unique_hosts = set()
    explicit_targets = []
    for line in lines:
        if ":" in line and not line.startswith(":"):
            explicit_targets.append(line)
        else:
            unique_hosts.add(line)

    # ==========================
    # 第一轮：快速扫描（高优端口 + 核心路径）
    # ==========================
    ROUND1_PORTS = [80, 443, 8080, 8443, 8888]
    ROUND1_PATHS = ["", "/", "/sub", "/subscribe", "/api/v1/client/subscribe"]

    round1_tasks = []
    for target in explicit_targets:
        host, port = target.rsplit(":", 1)
        for path in ROUND1_PATHS:
            round1_tasks.append((host, port, path))
    for host in unique_hosts:
        for port in ROUND1_PORTS:
            for path in ROUND1_PATHS:
                round1_tasks.append((host, str(port), path))

    print(f"[*] 第一轮快速扫描任务数: {len(round1_tasks)} | 历史记录: {len(history_data)} 条")

    pbar1 = tqdm(total=len(round1_tasks))
    hit_targets = set()

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)
    ) as session:
        for i in range(0, len(round1_tasks), WORKER_COUNT):
            batch = round1_tasks[i:i + WORKER_COUNT]
            results = await asyncio.gather(
                *(scan(session, h, p, path, pbar1) for h, p, path in batch)
            )
            for (h, p, path), is_hit in zip(batch, results):
                if is_hit:
                    hit_targets.add(f"{h}:{p}")

    # ==========================
    # 第二轮：完整扫描（针对第一轮未命中的目标跑全量端口和路径）
    # ==========================
    remaining_explicit = []
    for target in explicit_targets:
        if target not in hit_targets:
            remaining_explicit.append(target)

    round2_tasks = []
    for target in remaining_explicit:
        host, port = target.rsplit(":", 1)
        for path in PATHS:
            round2_tasks.append((host, port, path))
    for host in unique_hosts:
        for port in TARGET_PORTS:
            if f"{host}:{port}" not in hit_targets:
                for path in PATHS:
                    round2_tasks.append((host, str(port), path))

    if round2_tasks:
        print(f"\n[*] 第一轮已过滤大部分无效资产，开始第二轮完整扫描，剩余任务数: {len(round2_tasks)}")
        pbar2 = tqdm(total=len(round2_tasks))
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)
        ) as session:
            for i in range(0, len(round2_tasks), WORKER_COUNT):
                batch = round2_tasks[i:i + WORKER_COUNT]
                await asyncio.gather(
                    *(scan(session, h, p, path, pbar2) for h, p, path in batch)
                )
    else:
        print("\n[*] 第一轮已覆盖所有资产或无需进行第二轮扫描。")

    # 保存结果
    with open("scan_results.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["hash", "url", "host_port", "last_seen", "change_count", "last_hash"])
        for row in history_data.values():
            writer.writerow(row)

    print(f"\n[*] 扫描完成！共新增/更新: {stats['saved']} 个")

if __name__ == "__main__":
    asyncio.run(main())
