import aiohttp, asyncio, hashlib, os, csv, argparse, random, datetime, base64
from zoneinfo import ZoneInfo
from tqdm import tqdm

# --- 1. 基础配置 (核心收敛) ---
TARGET_PORTS = [80, 443, 8080, 8443, 8880, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 8888, 9999, 54321]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/v1/client/subscribe", "/config.yaml", "/clash", "/v2ray"]
SIGNS = [s.lower() for s in ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "hysteria://", "hy2://", "tuic://", "ss://"]]

WORKER_COUNT = 80
LIMIT_PER_HOST = 5
MAX_RESPONSE_SIZE = 300 * 1024 # 300KB
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "clash-verge/v1.3.8",
    "Shadowrocket/2.2.33"
]

stats = {"req": 0, "saved": 0, "err": 0}
history_data = {} 

# --- 2. 工具函数 ---

def normalize_url(url):
    return url.rstrip("/")

def is_base64_like(text):
    """精简后的 Base64 特征检查"""
    clean_text = "".join(text.split())
    if len(clean_text) < 30: return False
    # 由于已经 split()，此处不再需要检查空格和换行符
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(c in allowed for c in clean_text[:512])

def is_proxy_config(text):
    """命中逻辑判断"""
    if not text: return False
    
    # 1. 明文匹配 (缓存小写)
    lower_text = text.lower()
    if any(s in lower_text for s in SIGNS):
        return True
    
    # 2. Base64 匹配
    if is_base64_like(text):
        try:
            sample = "".join(text.split())[:512]
            padding = "=" * (-len(sample) % 4)
            decoded = base64.b64decode(sample + padding).decode("utf-8", errors="ignore").lower()
            if any(s in decoded for s in SIGNS):
                return True
        except:
            pass
    return False

def load_existing_results():
    if os.path.exists("scan_results.csv"):
        with open("scan_results.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) >= 7:
                    history_data[normalize_url(row[1])] = row

# --- 3. 核心扫描逻辑 ---

async def scan(session, host, port, path, pbar):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            async with session.get(url, timeout=4, ssl=False) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    # 响应头预检：跳过超大文件
                    cl = resp.headers.get("Content-Length")
                    if cl and int(cl) > MAX_RESPONSE_SIZE:
                        continue
                        
                    content = await resp.content.read(MAX_RESPONSE_SIZE)
                    text = content.decode("utf-8", errors="ignore")
                    
                    if is_proxy_config(text):
                        content_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                        content_type = resp.headers.get("Content-Type", "unknown").split(";")[0]
                        now_str = datetime.datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
                        norm_url = normalize_url(url)

                        # 保存快照 (不覆盖已存在的)
                        os.makedirs("results/hash", exist_ok=True)
                        file_suffix = hashlib.md5(norm_url.encode()).hexdigest()[:6]
                        filename = f"results/hash/{content_hash}_{file_suffix}.txt"
                        if not os.path.exists(filename):
                            with open(filename, "w", encoding="utf-8") as f:
                                f.write(text)

                        if norm_url not in history_data:
                            stats["saved"] += 1
                            pbar.write(f"[+] 发现新资产: {url} | {content_type}")
                            row = [content_hash, norm_url, f"{host}:{port}", now_str, 0, content_hash, content_type]
                        else:
                            old_row = history_data[norm_url]
                            change_inc = 1 if old_row[0] != content_hash else 0
                            row = [content_hash, norm_url, f"{host}:{port}", now_str, int(old_row[4]) + change_inc, old_row[0], content_type]
                        
                        history_data[norm_url] = row
                        pbar.update(1)
                        return # 命中即停
        except Exception:
            stats["err"] += 1
            continue
    pbar.update(1)

# --- 4. 主流程 ---

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    
    load_existing_results()
    
    with open(args.file) as f:
        lines = [l.strip() for l in f if l.strip()]
    
    tasks = []
    for line in lines:
        # 仅针对简单的 IPv4:Port 或 域名:Port 进行拆分，跳过 IPv6 复杂判断
        if ":" in line and "[" not in line:
            host, port = line.rsplit(":", 1)
            tasks.extend([(host, port, path) for path in PATHS])
        else:
            for port in TARGET_PORTS:
                tasks.extend([(line, port, path) for path in PATHS])

    print(f"[*] 任务总数: {len(tasks)} | 库内存放历史: {len(history_data)}")
    pbar = tqdm(total=len(tasks))
    
    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, limit_per_host=LIMIT_PER_HOST)
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        for i in range(0, len(tasks), WORKER_COUNT):
            batch = tasks[i:i+WORKER_COUNT]
            await asyncio.gather(*(scan(session, h, p, path, pbar) for h, p, path in batch))
            await asyncio.sleep(random.uniform(0.1, 0.2))
    
    # 保存结果 (排序后落地)
    with open("scan_results.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["hash", "url", "host_port", "last_seen", "change_count", "last_hash", "content_type"])
        for url_key in sorted(history_data.keys()):
            writer.writerow(history_data[url_key])
            
    print(f"\n[*] 扫描完成！请求: {stats['req']} | 成功: {len(history_data)} | 报错: {stats['err']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
