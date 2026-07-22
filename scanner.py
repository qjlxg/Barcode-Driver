import aiohttp, asyncio, hashlib, os, csv, argparse, random, datetime, base64
from zoneinfo import ZoneInfo
from tqdm import tqdm

# --- 配置 ---
TARGET_PORTS = [
    # 标准 Web 与加密服务
    80, 443,
    # Cloudflare 常用及配套端口
    8080, 8443, 8880, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096,
    # 常用面板、本地代理核心及高位端口
    1333, 1999, 2222, 3000, 3002, 3333, 4444, 5000, 5432, 5555, 6001, 6666, 7777,
    7890, 8000, 8010, 8011, 8081, 8083, 8181, 8787, 8888, 8899, 9000, 9050, 9090,
    9091, 9981, 9999, 10000, 10086, 10110, 12202, 18080, 19999, 20000, 30001,
    40000, 54321, 60001, 60002, 65432, 65533,
    # 补充的常用服务、系统管理及其他扩展冷门端口
    21, 22, 25, 53, 110, 143, 465, 587, 993, 995,
    1025, 1080, 1081, 1082, 1090, 1180, 1194, 1299, 1888,
    2000, 2001, 2002, 2020, 2021, 2022, 2030, 2031, 2040,
    2055, 2060, 2070, 2077, 2080, 2081, 2085, 2090,
    2100, 2111, 2121, 2200, 2255, 2333, 2375, 2376, 2555,
    3001, 3128, 3222, 3389, 4001, 5001, 5222, 5223,
    6000, 7000, 7001, 7070, 7077, 8001, 8082, 8084, 8085, 8086, 8088,
    8089, 8090, 8282, 8333, 8555, 8666, 8881, 8889, 9002, 9443, 9500, 9800,
    10101, 10443, 10809, 11223, 11443, 12000, 12345, 13000,
    14444, 15000, 16000, 17000, 18000, 19000, 21000,
    22000, 23000, 25000, 25565, 28080, 30000, 50000, 55000, 60000
]

PATHS = [
    # 基础与根目录
    "", "/", 
    # 基础订阅与分发路径
    "/sub", "/subscribe", "/subscription", "/sub2", "/sub3", "/subs",
    "/link", "/links", "/s/", "/get", "/getsub", "/getSub",
    # API 接口及各类版本订阅路径
    "/api/sub", "/api/subscribe", "/api/v1/subscribe", "/api/v2/subscribe",
    "/api/client/subscribe", "/user/subscribe", "/api/user/subscribe",
    "/api/v1/client/subscribe", "/api/v1/user/subscribe", "/client/subscribe",
    "/api/v1/sub", "/user/sub", "/api/sub/1", "/sub/1",
    # 常见客户端、面板及协议专属路径
    "/clash", "/clash/config", "/clash/proxies", "/v2ray", "/v2", "/vmess",
    "/ss", "/shadowsocks", "/trojan", "/hysteria", "/hy2", "/tuic",
    "/singbox", "/sb", "/mihomo", "/nekobox",
    # 隐蔽式短路径与常用管理路径
    "/getback8", "/auto", "/main.conf", "/clash.cfg", "/v2ray.txt", "/nodes",
    "/share", "/c", "/v", "/s", "/conf", "/dl", "/node", "/list", "/proxy",
    "/proxies", "/all", "/full", "/base64", "/b64", "/yaml", "/yml", "/json", "/txt",
    # 配置文件与静态模板路径
    "/config.yaml", "/sub.yaml", "/clash.yaml", "/clash.yml", "/config.yml",
    "/profile.yaml", "/profile.yml", "/config.json", "/setup.yaml",
    "/static/config.yaml", "/download/config.yml", "/download", "/download/sub", "/download/config",
    # 带参数的动态查询路径
    "/sub?target=clash", "/sub?target=v2ray", "/sub?target=singbox",
    "/sub?target=clash&ver=2", "/clash?type=clash", "/sub?format=clash",
    "/api/v1/client/sub?token=", "/user/sub?token=", "/link?sub=",
    "/s?token=", "/subscribe?token=", "/config?type=clash"
]

SIGNS = [s.lower() for s in [
    # Clash / Meta / Sing-box 核心配置关键字
    "proxies:", "proxy-groups:", "proxy-provider:", "proxy-providers:",
    "rule-providers:", "rules:", "mixed-port:", "allow-lan:", "mode:",
    "outbounds:", "inbounds:", "servers:", "dns:", "socks-port:",
    "redir-port:", "tproxy-port:", "policy-group", "proxy-group",
    "outbounds", "payload:",
    
    # 传统代理协议及链接
    "vless://", "vmess://", "trojan://", "ss://", "ssr://", "snell://",
    "shadowsocks://", "shadowsocks", "shadow-tls",
    
    # 现代高性能与加密代理协议
    "hysteria://", "hysteria2://", "hy2://", "hy://", "tuic://",
    "tuic-v5://", "anytls://", "juicity://", "reality://", "vless-reality://",
    "naive://", "wireguard", "ssh://", "relay",
    
    # 节点基础凭证与键值参数
    "uuid:", "passwd:", "password:", "server:", "port:", "sni:", "alpn:",
    "flow:", "method:", "cipher:", "server_name:", "skip-cert-verify:",
    "tls:", "network:",
    
    # JSON / 结构化键值特征
    "\"name\":", "\"server\":", "\"port\":", "\"password\":",
    "\"method\":", "\"cipher\":", "\"uuid\":", "\"flow\":",
    '"protocol"', '"server"',
    
    # 协议类型声明特征
    "type: vmess", "type: vless", "type: trojan", "type: shadowsocks",
    "type: hysteria", "type: hysteria2", "type: tuic",
    
    # 面板、转换器与客户端通用标识
    "sub-converter", "clash-config", "subscription-userinfo", "v2board",
    "[proxy]", "[server]", "clash", "sing-box", "subscription",
    "subscribe", "clash-for-windows", "clash.meta", "mihomo", "nekoray", "nekobox"
]]

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

def check_base64(text):
    try:
        sample = text[:500]
        decoded = base64.b64decode(
            sample + "=" * (-len(sample) % 4)
        ).decode(
            "utf-8",
            errors="ignore"
        )
        decoded_lower = decoded.lower()
        return any(
            s in decoded_lower
            for s in SIGNS
        )
    except:
        return False

async def scan(session, host, port, path, pbar):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            async with session.get(url, timeout=3, ssl=False) as resp:
                stats["req"] += 1
                if resp.status == 200:
                    text = await resp.text(errors="ignore")
                    lower_text = text.lower()
                    if any(s in lower_text for s in SIGNS) or check_base64(text):
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
