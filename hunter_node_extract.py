import asyncio
import aiohttp
import yaml
import csv
import os
import time
import hashlib
import ipaddress
import logging
import base64
from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple

# --- 配置 ---
INPUT_CSV = 'scan_results.csv'     
OUTPUT_FILE = 'unique.yaml'        
CSV_FILE = 'unique.csv'            
UNIQUE_URLS_FILE = 'unique_urls.txt'
RULES_FILE = 'rules.yaml'         
EXCLUDE_FILE = 'exclude.txt'      
BAD_WORDS = ["cf优选", "cf官方优选", "cloudflare优选", "免费测速", "剩余流量", "官网"]

# 抓取参数
CONCURRENCY = 100
LIMIT_PER_HOST = 20
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- 辅助函数 ---
def load_exclude_list() -> set:
    exclude_set = set()
    if os.path.exists(EXCLUDE_FILE):
        with open(EXCLUDE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    exclude_set.add(line.rstrip('/'))
    return exclude_set

def is_valid_server(server: Any) -> bool:
    if not server or not isinstance(server, str): 
        return False
    server = server.strip()
    blacklist = {"1.0.0.1", "1.1.1.1", "8.8.8.8", "255.255.255.255", "255.255.0.0", "255.0.0.0", "0.0.0.0", "127.0.0.1"}
    if server in blacklist: 
        return False
    try:
        ip = ipaddress.ip_address(server)
        return ip.is_global
    except ValueError:
        return True  # 域名默认通过

def stable_hash(node: Dict) -> str:
    keys = ["type", "server", "port", "uuid", "password", "cipher"]
    raw = "|".join(str(node.get(k, "")) for k in keys)
    return hashlib.md5(raw.encode()).hexdigest()

async def fetch_yaml(session: aiohttp.ClientSession, host: str) -> Tuple[str, int, str, float]:
    start_time = time.time()
    try:
        async with session.get(
            host, 
            timeout=aiohttp.ClientTimeout(connect=CONNECT_TIMEOUT, sock_read=READ_TIMEOUT),
            headers={"User-Agent": BROWSER_UA}, 
            allow_redirects=True
        ) as response:
            text = await response.text(errors='ignore')
            cost = round(time.time() - start_time, 2)
            return str(response.url), response.status, text, cost
    except Exception as e:
        logger.debug(f"请求失败 {host}: {e}")
        return host, 0, "", 0.0

def extract_yaml_nodes(text: str) -> List[Dict]:
    try:
        if "proxies:" in text.lower():
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "proxies" in data:
                nodes = []
                for n in data["proxies"]:
                    if isinstance(n, dict) and is_valid_server(n.get("server")):
                        node_name = str(n.get("name", ""))
                        if any(bad in node_name for bad in BAD_WORDS):
                            continue
                        nodes.append(n)
                return nodes
    except Exception:
        pass
    return []

async def process_source(session: aiohttp.ClientSession, source: str, semaphore: asyncio.Semaphore):
    async with semaphore:
        real_url, status, text, cost = await fetch_yaml(session, source)

    if not text: 
        return [source, "", "请求失败", 0, status, cost, ""], []
    
    nodes = extract_yaml_nodes(text)
    if not nodes: 
        summary = text[:150].replace('\r', ' ').replace('\n', ' ').replace('"', "'")
        return [source, "", "无有效节点", 0, status, cost, summary], []
        
    return [source, "", "提取成功", len(nodes), status, cost, ""], nodes

async def main():
    if not os.path.exists(INPUT_CSV):
        logger.error(f"未找到输入文件: {INPUT_CSV}")
        return

    # 1. 从 CSV 读取并去重
    exclude_list = load_exclude_list()
    with open(INPUT_CSV, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        urls = {row['url'].strip() for row in reader if row.get('url')}
        unique_urls = sorted(list({u.rstrip('/') for u in urls if u.rstrip('/') not in exclude_list}))

    with open(UNIQUE_URLS_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique_urls))

    logger.info(f"待处理 URL 总数: {len(unique_urls)}")

    # 2. 并发抓取
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY)
    ) as session:
        semaphore = asyncio.Semaphore(CONCURRENCY)
        results = await asyncio.gather(
            *(process_source(session, url, semaphore) for url in unique_urls)
        )

    # 3. 节点汇总与去重
    stats, all_nodes_map = [], {}
    for stat, nodes in results:
        stats.append(stat)
        for node in nodes:
            all_nodes_map[stable_hash(node)] = node

    # 4. 生成 YAML
    unique_nodes = list(all_nodes_map.values())

    final_config = {"proxies": unique_nodes}
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            rules_data = yaml.safe_load(f) or {}
            final_config = {**rules_data, "proxies": unique_nodes}
            if "proxy-groups" in final_config:
                node_names = [n.get("name") for n in unique_nodes if n.get("name")]
                for group in final_config["proxy-groups"]:
                    if group.get("name") in ["自动优选", "手动选择", "Nodes"]:
                        current_proxies = group.get("proxies", [])
                        new_proxies = [p for p in current_proxies if p not in node_names]
                        group["proxies"] = new_proxies + node_names

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False, width=1000)

    # 5. 保存 CSV 统计（关键修复）
    cleaned_stats = []
    for row in stats:
        cleaned_row = []
        for item in row:
            s = str(item)
            s = s.replace('"', "'")           # 双引号转单引号
            s = s.replace('\r', ' ').replace('\n', ' ')  # 移除换行
            s = s.replace('\t', ' ')          # 移除制表符
            cleaned_row.append(s)
        cleaned_stats.append(cleaned_row)

    with open(CSV_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(
            f, 
            quoting=csv.QUOTE_ALL,      # 关键修复
            escapechar='\\', 
            doublequote=True
        )
        writer.writerow(["原始URL", "资产地址", "状态", "节点数", "HTTP码", "响应秒数", "摘要"])
        writer.writerows(cleaned_stats)

    logger.info(f"处理完成，生成唯一节点数: {len(unique_nodes)}")

if __name__ == "__main__":
    asyncio.run(main())