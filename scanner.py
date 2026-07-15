import aiohttp, asyncio, hashlib, os, csv, argparse
from tqdm import tqdm
from datetime import datetime

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]
HIGH_VALUE_SIGNS = ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]
WORKER_COUNT = 50 
MAX_SIZE = 300 * 1024 

DB_FILE = "scan_results.csv"
FIELDS = ["hash", "url", "host_port", "first_seen", "last_seen", "last_cycle", "status", "miss_count"]

stats = {"req": 0, "saved": 0, "update": 0, "error": 0}
asset_db = {}

def migrate_old_db():
    if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0: return
    with open(DB_FILE, encoding="utf-8") as f: first_line = f.readline().strip()
    if "first_seen" in first_line: return 

    old_rows = []
    with open(DB_FILE, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("host_port"): old_rows.append(row)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in old_rows:
            writer.writerow({"hash": row.get("hash", ""), "url": row.get("url", ""), "host_port": row.get("host_port", ""), "first_seen": now, "last_seen": now, "last_cycle": "0", "status": "active", "miss_count": "0"})
    os.replace(tmp, DB_FILE)

def load_db():
    migrate_old_db()
    if os.path.exists(DB_FILE):
        with open(DB_FILE, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("host_port"): asset_db[row["host_port"]] = row

def save_db():
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in asset_db.values(): writer.writerow(row)
    os.replace(tmp, DB_FILE)

def update_asset(host_port, url, md5, cycle):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if host_port in asset_db:
        asset_db[host_port].update({"hash": md5, "url": url, "last_seen": now, "last_cycle": cycle, "status": "active", "miss_count": "0"})
        return "update"
    else:
        asset_db[host_port] = {"hash": md5, "url": url, "host_port": host_port, "first_seen": now, "last_seen": now, "last_cycle": cycle, "status": "active", "miss_count": "0"}
        return "new"

async def scan(session, host, port, path, pbar, cycle):
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
                        res = update_asset(f"{host}:{port}", url, content_hash, cycle)
                        if res == "new":
                            stats["saved"] += 1
                            pbar.write(f"[+] 发现新资产: {url}")
                            os.makedirs("results/hash", exist_ok=True)
                            with open(f"results/hash/{content_hash}.txt", "w", encoding="utf-8") as f: f.write(text)
                        else:
                            stats["update"] += 1
                        return 
    except Exception: stats["error"] += 1
    finally: pbar.update(1)

async def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--file", required=True); parser.add_argument("--cycle", type=int, default=0); args = parser.parse_args()
    load_db()

    with open(args.file) as f: lines = [l.strip() for l in f if l.strip()]
    tasks = []
    for line in lines:
        if ":" in line:
            host, port = line.rsplit(":", 1)
            for path in PATHS: tasks.append((host, port, path))
        else:
            for port in TARGET_PORTS:
                for path in PATHS: tasks.append((line, port, path))

    print(f"[*] 任务总数: {len(tasks)} | 资产池规模: {len(asset_db)}")
    pbar = tqdm(total=len(tasks))
    connector = aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=5, connect=3)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for i in range(0, len(tasks), WORKER_COUNT):
            await asyncio.gather(*(scan(session, h, p, path, pbar, args.cycle) for h, p, path in tasks[i:i+WORKER_COUNT]))

    save_db()
    print(f"\n[*] 扫描完成 | 新增: {stats['saved']} | 更新: {stats['update']} | 错误: {stats['error']}")

if __name__ == "__main__": asyncio.run(main())
