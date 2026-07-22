import re
import json
import base64
import ipaddress
import requests
from pathlib import Path
from datetime import datetime
import time
import random
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 配置 ======================
CONFIG_DIR = Path("config")
DATA_DIR = Path("data")
IP_FILE = Path("ip.txt")
FRESH_LOG = DATA_DIR / "fresh_seeds_log.json"
SOURCES_FILE = Path("sources.txt")

# 请求头
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

# 并发配置
MAX_WORKERS = 15          # 最大并发数（可根据情况调到 10~20）
TIMEOUT = 5

# ==================== 辅助函数 ====================
def load_sources():
    if not SOURCES_FILE.exists():
        print(f"警告: {SOURCES_FILE} 不存在")
        return []
    return [line.strip() for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith('#')]


def try_base64_decode(text: str) -> str:
    clean_s = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    if len(clean_s) < 20:
        return text
    try:
        missing = len(clean_s) % 4
        if missing:
            clean_s += '=' * (4 - missing)
        decoded = base64.b64decode(clean_s).decode('utf-8', errors='ignore')
        return text + "\n" + decoded
    except:
        return text


def is_github_url(url: str) -> bool:
    return "github.com" in url.lower()


def extract_ips_and_domains(text: str, url: str = ""):
    found_items = set()

    # CIDR
    for match in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:2[4-9]|3[0-2])\b', text):
        try:
            net = ipaddress.ip_network(match, strict=False)
            if not net.is_private and not net.is_loopback and not net.is_reserved:
                found_items.add(str(net))
        except:
            continue

    # IPv4
    for match in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text):
        try:
            ip_obj = ipaddress.ip_address(match)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                continue
            if is_github_url(url):
                github_cdn = ["185.199.108.0/22", "140.82.112.0/20", "192.30.252.0/22",
                              "13.248.224.0/24", "76.76.21.0/24", "20.207.0.0/16"]
                if any(ip_obj in ipaddress.ip_network(r) for r in github_cdn):
                    continue
            net = ipaddress.ip_network(f"{match}/24", strict=False)
            found_items.add(str(net))
        except:
            continue
    return found_items


def collect_from_url(url: str):
    """单个URL抓取"""
    try:
        print(f"[+] 正在抓取: {url}")
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

        if resp.status_code != 200:
            print(f"    └─ 状态码异常: {resp.status_code}")
            return url, set()

        processed = try_base64_decode(resp.text)
        found = extract_ips_and_domains(processed, url)

        count = len(found)
        if is_github_url(url) and count > 0:
            print(f"    └─ 成功提取到 {count} 个合法网段（已过滤 GitHub）")
        else:
            print(f"    └─ 成功提取到 {count} 个合法网段")
        return url, found
    except Exception as e:
        print(f"    └─ 抓取失败: {e}")
        return url, set()


def main():
    print(f"[{datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')}] 开始收集新鲜种子...\n")

    SOURCES = load_sources()
    if not SOURCES:
        print("没有找到数据源，退出。")
        return

    all_new_items = set()
    start_time = time.time()

    # ============== 并发抓取 ==============
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(collect_from_url, url): url for url in SOURCES}
        
        for future in as_completed(future_to_url):
            url, items = future.result()
            all_new_items.update(items)

    elapsed = time.time() - start_time

    # ============== 保存结果 ==============
    existing = set()
    if IP_FILE.exists():
        existing = {line.strip() for line in IP_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}

    really_new = all_new_items - existing
    combined = existing.union(all_new_items)
    clean_combined = sorted(x for x in combined if x)

    IP_FILE.write_text("\n".join(clean_combined), encoding="utf-8")

    # 日志
    DATA_DIR.mkdir(exist_ok=True)
    log_entry = {
        "time": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
        "new_count": len(really_new),
        "total_now": len(clean_combined),
        "sources_checked": len(SOURCES),
        "duration_seconds": round(elapsed, 2)
    }
    try:
        history = json.loads(FRESH_LOG.read_text(encoding="utf-8")) if FRESH_LOG.exists() else []
        history.append(log_entry)
        FRESH_LOG.write_text(json.dumps(history[-100:], indent=2, ensure_ascii=False), encoding="utf-8")
    except:
        pass

    print("\n" + "=" * 60)
    print(f"收集完成！用时 {elapsed:.1f} 秒")
    print(f"本次新增有效网段: {len(really_new)} 个")
    print(f"当前总种子数: {len(clean_combined)} 个")
    print(f"已更新 → {IP_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
