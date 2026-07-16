import asyncio
import aiohttp
import yaml
import hashlib
import os
import csv
import logging
import ipaddress
import time
import base64
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple

# === 配置参数 ===
INPUT_FILE = "hunter_result.txt"
OUTPUT_FILE = "hunter_nodes.yaml"
CSV_FILE = "hunter_node_extract.csv"
RULES_FILE = "rules.yaml"
EXCLUDE_FILE = "exclude.txt"  # 排除列表文件
CONCURRENCY = 100       # 并发数
LIMIT_PER_HOST = 20     # 提升限制以适配多端口扫描
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def load_exclude_list() -> set:
    """读取排除文件，支持域名或域名:端口"""
    exclude_set = set()
    if os.path.exists(EXCLUDE_FILE):
        with open(EXCLUDE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    exclude_set.add(line.rstrip('/'))
    return exclude_set

def is_valid_server(server: Any) -> bool:
    if not server or not isinstance(server, str): return False
    server = server.strip()
    blacklist = {"1.0.0.1", "1.1.1.1", "8.8.8.8", "255.255.255.255", "255.255.0.0", "255.0.0.0", "0.0.0.0", "127.0.0.1"}
    if server in blacklist: return False
    try:
        ip = ipaddress.ip_address(server)
        return ip.is_global
    except ValueError:
        if "." in server and " " not in server and len(server) > 3:
            parts = server.split('.')
            if all(p.isdigit() for p in parts) and len(parts) == 4: return False
            return True
        return False

def stable_hash(node: Dict) -> str:
    """基于核心字段进行去重"""
    keys = ["type", "server", "port", "uuid", "password", "cipher"]
    raw = "|".join(str(node.get(k, "")) for k in keys)
    return hashlib.md5(raw.encode()).hexdigest()

async def fetch_yaml(session: aiohttp.ClientSession, host: str) -> Tuple[str, int, str, float]:
    """增强版获取：支持多协议识别"""
    if not host.lower().startswith(("http://", "https://")):
        target_urls = [f"https://{host}", f"http://{host}"]
    else:
        target_urls = [host]

    for url in target_urls:
        start_time = time.time()
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(connect=CONNECT_TIMEOUT, sock_read=READ_TIMEOUT),
                                   headers={"User-Agent": BROWSER_UA}, allow_redirects=True) as response:
                text = await response.text(errors='ignore')
                cost = round(time.time() - start_time, 2)
                content_lower = text.lower()
                
                # 增强判断逻辑
                if response.status < 300 and any(k in content_lower for k in [
                    "proxies:", "proxy-providers:", "vmess://", "vless://", "trojan://", "ss://", "ssr://", "hy2://"
                ]):
                    return str(response.url), response.status, text, cost
                if url == target_urls[-1]: return str(response.url), response.status, text, cost
        except Exception: continue
    return host, 0, "", 0.0

def extract_yaml_nodes(text: str) -> List[Dict]:
    try:
        # 尝试处理 Base64
        if "://" not in text and len(text) > 10:
            try:
                text = base64.b64decode(text).decode('utf-8', errors='ignore')
            except: pass
            
        if "proxies:" in text.lower():
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                return [n for n in data["proxies"] if isinstance(n, dict) and is_valid_server(n.get("server"))]
    except Exception: pass
    return []

async def process_source(session: aiohttp.ClientSession, source: str, semaphore: asyncio.Semaphore):
    p = urlparse(source if "://" in source else f"http://{source}")
    host_port = f"{p.hostname}:{p.port}" if p.port else p.hostname
    
    async with semaphore:
        real_url, status, text, cost = await fetch_yaml(session, source)
    
    if not text: return [source, host_port, "请求失败", 0, status, cost, ""], []
    nodes = extract_yaml_nodes(text)
    if not nodes: return [source, host_port, "无有效节点", 0, status, cost, text[:100].replace('\n', ' ')], []
    return [source, host_port, "提取成功", len(nodes), status, cost, ""], nodes

def upload_to_gist(file_path):
    """上传指定文件到 Gist"""
    gist_id = os.getenv("GIST_ID")
    token = os.getenv("GIST_TOKEN")
    if not gist_id or not token:
        logger.warning("缺少 GIST_ID 或 GIST_TOKEN，跳过上传")
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
        data = {"files": {file_path: {"content": content}}}
        
        response = requests.patch(f"https://api.github.com/gists/{gist_id}", headers=headers, json=data)
        if response.status_code == 200:
            logger.info(f"成功上传 {file_path} 到 Gist")
        else:
            logger.error(f"上传失败: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"上传异常: {e}")

async def main():
    if not os.path.exists(INPUT_FILE): return
    
    exclude_list = load_exclude_list()
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        urls_raw = [l.strip() for l in f if l.strip()]
        unique_urls = sorted(list({u.rstrip('/') for u in urls_raw if u.rstrip('/') not in exclude_list}))

    logger.info(f"待处理 URL 总数: {len(unique_urls)}")

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=CONCURRENCY, limit_per_host=LIMIT_PER_HOST, ssl=False), 
                                     timeout=aiohttp.ClientTimeout(total=30)) as session:
        semaphore = asyncio.Semaphore(CONCURRENCY)
        results = await asyncio.gather(*(process_source(session, url, semaphore) for url in unique_urls))

    stats, all_nodes_map = [], {}
    for stat, nodes in results:
        stats.append(stat)
        for node in nodes:
            all_nodes_map[stable_hash(node)] = node

    unique_nodes = list(all_nodes_map.values())
    logger.info(f"抓取完成。唯一节点: {len(unique_nodes)}")

    final_config = {"proxies": unique_nodes}
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            rules_data = yaml.safe_load(f) or {}
            final_config = {**rules_data, "proxies": unique_nodes}
            if "proxy-groups" in final_config:
                node_names = [n.get("name") for n in unique_nodes if n.get("name")]
                for group in final_config["proxy-groups"]:
                    if group.get("name") in ["自动优选", "手动选择", "Nodes"]:
                        group["proxies"] = node_names

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False, width=1000)

    stats.sort(key=lambda x: int(x[3]), reverse=True)
    with open(CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["原始URL", "资产地址", "状态", "节点数", "HTTP码", "响应秒数", "内容摘要"])
        writer.writerows(stats)

if __name__ == "__main__":
    asyncio.run(main())
    upload_to_gist(OUTPUT_FILE)