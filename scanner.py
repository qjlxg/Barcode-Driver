import aiohttp, asyncio, hashlib, os, csv, argparse
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]
HIGH_VALUE_SIGNS = ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]
WORKER_COUNT = 50 
MAX_SIZE = 300 * 1024 

stats = {"req": 0, "saved": 0, "error": 0}
visited_hashes = set()

def load_existing_results():
    if os.path.exists("scan_results.csv"):
        with open("scan_results.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0] not in ("hash", ""):
                    visited_hashes.add(row[0])
    else:
        with open("scan_results.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(['hash', 'url', 'host_port'])

async def scan(session, host, port, path, pbar):
    try:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}:{port}{path}"
            async with session.get(url, ssl=False) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    data = await resp.content.read(MAX_SIZE)
                    text = data.decode("utf-8", errors="ignore")
                    if any(s in text.lower() for s in HIGH_VALUE_SIGNS):
                        content_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                        if content_hash not in visited_hashes:
                            visited_hashes.add(content_hash)
                            stats["saved"] += 1
                            pbar.write(f"[+] 发现新资产: {url}")
                            os.makedirs("results/hash", exist_ok=True)
                            with open(f"results/hash/{content_hash}.txt", "w", encoding="utf-8") as f:
                                f.write(text)
                            with open("scan_results.csv", "a", encoding="utf-8", newline="") as f:
                                csv.writer(f).writerow([content_hash, url, f"{host}:{port}"])
                        return 
    except Exception:
        stats["error"] += 1
    finally:
        pbar.update(1)

async def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--file", required=True); args = parser.parse_args()
    load_existing_results()

    with open(args.file) as f: lines = [l.strip() for l in f if l.strip()]

    tasks = []
    for line in lines:
        if ":" in line:
            host, port = line.rsplit(":", 1)
            for path in PATHS: tasks.append((host, port, path))
        else:
            for port in TARGET_PORTS:
                for path in PATHS: tasks.append((line, port, path))

    print(f"[*] 任务总数: {len(tasks)} | 已排除 {len(visited_hashes)} 个旧指纹")
    pbar = tqdm(total=len(tasks))

    # 统一化连接与超时配置
    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=5, connect=3)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for i in range(0, len(tasks), WORKER_COUNT):
            await asyncio.gather(*(scan(session, h, p, path, pbar) for h, p, path in tasks[i:i+WORKER_COUNT]))

    print(f"\n[*] 扫描完成！新增: {stats['saved']} | 错误: {stats['error']}")

if __name__ == "__main__": asyncio.run(main())
