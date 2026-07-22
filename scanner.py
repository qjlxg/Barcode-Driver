import aiohttp, asyncio, hashlib, os, csv, argparse, random, datetime
from zoneinfo import ZoneInfo
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [80, 443, 1333, 1999, 2052, 2053, 2082, 2083, 2087, 2095, 2096, 2222, 3002, 3333, 4444, 5555, 6001, 6666, 7777, 8011, 8080, 8081, 8083, 8443, 8444, 8787, 8888, 8899, 9050, 9981, 9999, 10110, 12202, 18080, 19999, 54321, 60001, 60002]
PATHS = ["", "/", "/sub", "/subscribe", "/link", "/s/", "/api/sub", "/api/v1/client/subscribe", "/api/user/subscribe", "/client/subscribe", "/config.yaml", "/sub.yaml"]
SIGNS = [s.lower() for s in ["proxies:", "proxy-groups:", "vless://", "vmess://", "trojan://","hysteria://", "hysteria2://", "hy2://", "tuic://", "anytls://"]]
WORKER_COUNT = 100 

stats = {"req": 0, "saved": 0}
# 记录历史资产数据：{url: [hash, url, host_port, last_seen, change_count, last_hash]}
history_data = {}

def normalize_url(url):
    return url.rstrip("/")

def load_existing_results():
    """加载历史记录以实现去重与更新"""
    if os.path.exists("scan_results.csv"):
        with open("scan_results.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None) # 跳过表头
            for row in reader:
                if len(row) >= 6:
                    # hash, url, host_port, last_seen, change_count, last_hash
                    history_data[normalize_url(row[1])] = row
                elif len(row) >= 2:
                    # 兼容旧格式
                    history_data[normalize_url(row[1])] = [row[0], row[1], "", datetime.datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d"), 0, row[0]]

async def scan(session, host, port, path, pbar):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            async with session.get(url, timeout=3, ssl=False) as resp:
                stats["req"] += 1
                if resp.status != 200:
                    continue
                text = await resp.text(errors="ignore")
                text_lower = text.lower()
                text_stripped = text.strip()
                
                # ==================== 防误报过滤 ====================
                # 1. 明显是网页的直接跳过
                if (text_stripped.startswith('<!doctype') or 
                    '<html' in text_lower[:300] or 
                    '<head>' in text_lower[:500] or 
                    len(text) > 800000):
                    continue
                
                # 2. 必须包含有效代理特征
                has_sign = any(s in text_lower for s in SIGNS)
                if not has_sign:
                    continue
                
                # 3. 严格过滤只含 "proxies:" 的情况
                if ("proxies:" in text_lower and 
                    not any(x in text_lower for x in ["proxy-groups:", "vless://", "vmess://", "trojan://", "hysteria", "tuic://", "ss://"])):
                    continue
                
                # 4. 额外过滤：太短或明显不是订阅内容的也跳过
                if len(text) < 100 or "404 not found" in text_lower or "not found" in text_lower[:200]:
                    continue
                # ==================================================
                
                # 计算当前指纹
                content_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:12]
                now_str = datetime.datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
                
                norm_url = normalize_url(url)
                # 强制落地备份 (保存内容哈希及来源标识)
                os.makedirs("results/hash", exist_ok=True)
                file_suffix = hashlib.md5(norm_url.encode()).hexdigest()[:6]
                filename = f"results/hash/{content_hash}_{file_suffix}.txt"
                if not os.path.exists(filename):
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(text)

                if norm_url not in history_data:
                    # 新资产
                    stats["saved"] += 1
                    pbar.write(f"[+] 发现新节点: {url}")
                    row = [content_hash, norm_url, f"{host}:{port}", now_str, 0, content_hash]
                else:
                    # 已知资产，检查变更
                    old_row = history_data[norm_url]
                    if old_row[0] != content_hash:
                        pbar.write(f"[*] 发现内容变更: {url}")
                        row = [content_hash, norm_url, f"{host}:{port}", now_str, int(old_row[4]) + 1, old_row[0]]
                    else:
                        # 无变更，仅更新最后探测时间
                        old_row[3] = now_str
                        row = old_row
                
                history_data[norm_url] = row
                pbar.update(1)
                return # 找到即停止尝试该端口
                    
        except asyncio.TimeoutError: 
            continue
        except Exception: 
            continue
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

    print(f"[*] 任务总数: {len(tasks)} | 已加载 {len(history_data)} 条历史记录")
    pbar = tqdm(total=len(tasks))
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=WORKER_COUNT)) as session:
        for i in range(0, len(tasks), WORKER_COUNT):
            batch = tasks[i:i+WORKER_COUNT]
            await asyncio.gather(*(scan(session, h, p, path, pbar) for h, p, path in batch))
    
    # 扫描完成后，写入表头并重写 CSV
    with open("scan_results.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["hash", "url", "host_port", "last_seen", "change_count", "last_hash"])
        for norm_url in history_data:
            writer.writerow(history_data[norm_url])
            
    print(f"\n[*] 扫描完成！共新增/更新: {stats['saved']} 个")

if __name__ == "__main__": asyncio.run(main())
