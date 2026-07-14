import aiohttp, asyncio, hashlib, os, csv, argparse, random
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]
SIGNS = ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://", "uuid:", "hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]
WORKER_COUNT = 100 

stats = {"req": 0, "saved": 0}
# 记录已扫描的指纹，避免重复处理
visited_hashes = set()

def load_existing_results():
    """加载历史记录以实现去重"""
    if os.path.exists("scan_results.csv"):
        with open("scan_results.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row: visited_hashes.add(row[0]) # 假设第一列是 hash

async def scan(session, host, port, path, pbar):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            async with session.get(url, timeout=3, ssl=False) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    if any(s in text.lower() for s in SIGNS):
                        # 计算指纹
                        content_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                        
                        if content_hash not in visited_hashes:
                            visited_hashes.add(content_hash)
                            stats["saved"] += 1
                            
                            # 实时日志显示
                            pbar.write(f"[+] 发现新节点: {url}")
                            
                            # 保存文件
                            os.makedirs("results/hash", exist_ok=True)
                            with open(f"results/hash/{content_hash}.txt", "w", encoding="utf-8") as f:
                                f.write(text)
                            
                            # 写入 CSV
                            with open("scan_results.csv", "a", encoding="utf-8", newline="") as f:
                                writer = csv.writer(f)
                                writer.writerow([content_hash, url])
                                
                        return # 找到即停止尝试该端口
        except: continue
    pbar.update(1)

async def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--file", required=True); args = parser.parse_args()
    load_existing_results() # 启动时加载历史记录
    
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
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)) as session:
        for i in range(0, len(tasks), WORKER_COUNT):
            batch = tasks[i:i+WORKER_COUNT]
            await asyncio.gather(*(scan(session, h, p, path, pbar) for h, p, path in batch))
            
    print(f"\n[*] 扫描完成！共新增: {stats['saved']} 个")

if __name__ == "__main__": asyncio.run(main())
