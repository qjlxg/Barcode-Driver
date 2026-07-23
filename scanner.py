import aiohttp
import asyncio
import hashlib
import os
import csv
import argparse
import datetime
import re
import base64
from zoneinfo import ZoneInfo
from tqdm import tqdm

# ==========================
# 配置（已合并去重 + 优化）
# ==========================

# 独立的 HTTP Header 高优先级特征（严格分为直接信任与需二次校验）
HEADER_SIGNS = [s.lower() for s in [
    "subscription-userinfo",
    "profile-update-interval",
    "v2rayn-sub"
]]

# 弱特征/特征线索：命中的话需要继续进行正文校验，不能直接放行
HEADER_WEAK_SIGNS = [s.lower() for s in [
    "basehttp/0.6 python",
    "simplehttp/0.6 python",
    "content-disposition"
]]

# Body 强特征（保留定义，但不单独作为盲目信任保存的直接条件，需配合结构或协议校验）
BODY_STRONG_SIGNS = [s.lower() for s in [
    "clash-party.yaml",
    "proxies:",
    "proxy-providers:",
    "proxy-groups:",
    "outbounds:"
]]

# 普通特征（保留原结构，不作为直接保存条件）
NORMAL_SIGNS = [s.lower() for s in [
    "proxy-group:",
    "rules:",
    "mixed-port:",
    "allow-lan:",
    "mode:",
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "anytls://",
    "inbounds:",
    "servers:",
    "reality:",
    "[proxy]",
    "[server]",
    "policy-group",
    "clash",
    "sing-box",
    "mihomo",
    "nekobox",
    "nekoray",
    "type: vmess",
    "type: vless",
    "type: trojan",
    "type: shadowsocks",
    "type: hysteria",
    "type: hysteria2",
    "skip-cert-verify:"
]]

# 垃圾页面特征
BLACK_SIGNS = [s.lower() for s in [
    "wordpress",
    "wp-content",
    "gitlab",
    "plesk",
    "fastpanel",
    "just a moment",
    "checking your browser",
    "enable javascript",
    "wix.com"
]]

# 目标端口
TARGET_PORTS = [
    80, 443,
    2052, 2053, 2082, 2083, 2095, 2096,
    8080, 8443, 8888, 12202
]

WORKER_COUNT = 150
MAX_SIZE = 300 * 1024

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


def looks_like_base64(text):
    t = text.strip()
    if len(t) < 100:
        return False
    # Base64字符检查
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", t):
        return False
    try:
        decoded = base64.b64decode(t + "===", validate=False)
        d = decoded.decode(errors="ignore").lower()
        count = 0
        for x in [
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
            "hysteria2://"
        ]:
            count += d.count(x)
        return count >= 2
    except Exception:
        return False


def check_yaml_structure(text):
    if re.search(r"^proxies\s*:", text, re.M):
        return True
    if re.search(r"^proxy-groups\s*:", text, re.M):
        return True
    if re.search(r"^proxy-providers\s*:", text, re.M):
        return True
    if re.search(r"^outbounds\s*:", text, re.M):
        return True
    return False


def count_protocols(text):
    count = 0
    for p in [
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "anytls://"
    ]:
        count += text.count(p)
    return count


def count_yaml_nodes(text):
    return len(re.findall(r"\n\s*-\s*name\s*:", text, re.I))


async def save_result(url, text, host, port, pbar):
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
        row = [
            content_hash,
            norm_url,
            f"{host}:{port}",
            now_str,
            0,
            content_hash
        ]
    else:
        old_row = history_data[norm_url]
        if old_row[0] != content_hash:
            pbar.write(f"[*] 内容已更新: {url}")
            row = [
                content_hash,
                norm_url,
                f"{host}:{port}",
                now_str,
                int(old_row[4]) + 1,
                old_row[0]
            ]
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
                headers={"User-Agent": "Mozilla/5.0"}
            ) as resp:

                stats["req"] += 1

                if resp.status != 200:
                    continue

                content_type = resp.headers.get("content-type", "").lower()
                header_text = str(resp.headers).lower()

                # ======================
                # 一级 Header 高价值判断
                # ======================
                # 只有真正的高价值强标识（如 subscription-userinfo 等）才直接信任并保存
                if any(s in header_text for s in HEADER_SIGNS):
                    data = await resp.content.read(MAX_SIZE)
                    text = data.decode(errors="ignore")

                    if len(text.strip()) < 200:
                        continue

                    if "text/html" in content_type and "<html" in text[:500].lower():
                        continue

                    stats["saved"] += 1
                    pbar.write(f"[+] 高优先级发现: {url}")
                    await save_result(url, text, host, port, pbar)
                    pbar.update(1)
                    return True

                # ======================
                # 二级 Body 判断
                # ======================
                data = await resp.content.read(MAX_SIZE)
                text = data.decode(errors="ignore")

                if len(text.strip()) < 200:
                    continue

                lower_text = text.lower()
                head = lower_text[:500]

                if "<html" in head or "<!doctype" in head:
                    continue

                if any(s in lower_text for s in BLACK_SIGNS):
                    continue

                protocol_count = count_protocols(lower_text)
                node_count = count_yaml_nodes(text)
                valid = False

                if protocol_count >= 2:
                    valid = True

                if check_yaml_structure(text):
                    if node_count >= 1 or protocol_count >= 1:
                        valid = True

                if looks_like_base64(text):
                    valid = True

                # 如果命中了诸如 basehttp 等弱特征 Header，则强行要求正文必须通过结构或协议校验，不能仅凭 BODY_STRONG_SIGNS 放行
                has_weak_header = any(s in header_text for s in HEADER_WEAK_SIGNS)
                
                if not has_weak_header:
                    for sign in BODY_STRONG_SIGNS:
                        if sign in lower_text:
                            valid = True
                            break

                if not valid:
                    continue

                # ======================
                # 评分系统
                # ======================
                score = 0
                if protocol_count >= 2:
                    score += 5
                if node_count >= 2:
                    score += 3
                if check_yaml_structure(text):
                    score += 3
                if protocol_count > 0:
                    score += 5
                if looks_like_base64(text):
                    score += 5

                if score < 5:
                    continue

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

    unique_hosts = set()
    explicit_targets = []

    for line in lines:
        if ":" in line and not line.startswith(":"):
            explicit_targets.append(line)
        else:
            unique_hosts.add(line)

    # ==========================
    # 第一轮快速扫描
    # ==========================
    ROUND1_PORTS = [80, 443, 8080, 8443, 8888]
    ROUND1_PATHS = [
        "",
        "/",
        "/sub",
        "/subscribe",
        "/api/v1/client/subscribe",
        "/config.yaml",
        "/clash.yaml",
        "/sub.yaml"
    ]

    round1_tasks = []

    for target in explicit_targets:
        host, port = target.rsplit(":", 1)
        for path in ROUND1_PATHS:
            round1_tasks.append((host, port, path))

    for host in unique_hosts:
        for port in ROUND1_PORTS:
            for path in ROUND1_PATHS:
                round1_tasks.append((host, str(port), path))

    print(f"[*] 扫描任务数: {len(round1_tasks)} | 历史记录: {len(history_data)} 条")

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

            for item, is_hit in zip(batch, results):
                if is_hit:
                    h, p, path = item
                    hit_targets.add(f"{h}:{p}")

    # 保存结果
    with open("scan_results.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "hash",
            "url",
            "host_port",
            "last_seen",
            "change_count",
            "last_hash"
        ])
        for row in history_data.values():
            writer.writerow(row)

    print(f"\n[*] 扫描完成！共新增/更新: {stats['saved']} 个")


if __name__ == "__main__":
    asyncio.run(main())
