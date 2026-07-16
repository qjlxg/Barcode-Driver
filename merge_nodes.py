import yaml
import glob
import hashlib
import json
import os
from datetime import datetime, timedelta
import itertools
from urllib.parse import urlparse, parse_qs
from collections import Counter

REGISTRY_FILE = 'node_registry.json'
MAX_IDLE_DAYS = 30
# 统一维护协议集
EXPORT_TYPES = {'vless', 'hysteria', 'hysteria2', 'tuic', 'anytls'}
# 优化：增强哈希因子
HASH_KEYS = ["type", "server", "port", "uuid", "password", "flow", "network", "tls", "reality-opts", "sni", "servername", "client-fingerprint"]
BAD_WORDS = ["cf优选", "cloudflare优选", "免费测速", "剩余流量", "官网"]
TODAY = datetime.now().strftime("%Y-%m-%d")

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, 'r') as f:
                data = json.load(f)
                return data.get("nodes", {}) if isinstance(data, dict) and "nodes" in data else data
        except Exception as e:
            print(f"[WARN] Failed to load registry: {e}")
            return {}
    return {}

def save_registry(registry):
    with open(REGISTRY_FILE, 'w') as f: 
        json.dump({"version": 2, "nodes": registry}, f, indent=2)

def get_node_hash(p):
    filtered_node = {k: p[k] for k in HASH_KEYS if k in p}
    return hashlib.md5(json.dumps(filtered_node, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()

def score_node(p, registry):
    h = get_node_hash(p)
    hist = registry.get(h, {})
    score = 0
    try:
        first = datetime.strptime(hist.get('first_seen', TODAY), "%Y-%m-%d")
        score += min(max((datetime.now() - first).days + 1, 1), 5)
    except: score += 1
    s, f = hist.get('success', 0), hist.get('fail', 0)
    if s + f > 0: score += (s / (s + f)) * 5
    if hist.get("latest_ms"):
        if hist["latest_ms"] < 100: score += 3
        elif hist["latest_ms"] < 200: score += 2
    score += min(len(hist.get("source_map", {})), 2)
    t = str(p.get('type', '')).lower()
    score += {'hysteria2': 3, 'hysteria': 3, 'tuic': 3, 'vless': 3, 'anytls': 2}.get(t, 0)
    if t in ['hysteria2', 'tuic']: score += 1
    if str(p.get('udp', '')).lower() == 'true': score += 1
    if p.get('reality-opts') or p.get('reality'): score += 3
    elif p.get('tls'): score += 1
    return score

def parse_txt_line(line):
    try:
        if '://' not in line: return None
        parts = urlparse(line)
        query = parse_qs(parts.query)
        node = {"type": parts.scheme.lower(), "server": parts.hostname, "port": parts.port or 443, "name": parts.fragment or "imported-node"}
        
        if node["type"] == "vless": node["uuid"] = parts.username
        elif node["type"] in ["hysteria", "hysteria2"]: node["password"] = parts.username
        elif node["type"] == "tuic": node["uuid"], node["password"] = parts.username, parts.password
        
        if "sni" in query: node["sni"] = query["sni"][0]
        if "security" in query: node["tls"] = True
        return node
    except: return None

def fix_names(nodes):
    used = set()
    for p in nodes:
        name = p.get("name", "node")
        short = get_node_hash(p)[:6]
        final_name = f"{name}-{short}"
        # 避免使用动态内存ID，确保名称唯一且稳定
        if final_name in used: final_name = f"{name}-{short}-dup"
        used.add(final_name)
        p["name"] = final_name
    return nodes

def merge_yaml_nodes():
    registry = load_registry()
    all_nodes, seen_hashes = [], set()
    raw_total, valid_total = 0, 0
    
    files = itertools.chain(glob.glob("results/hash/*.yaml"), glob.glob("results/hash/*.txt"))
    for file_path in files:
        try:
            nodes_in_file = []
            if file_path.endswith('.yaml'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'proxies' in data: nodes_in_file = data['proxies']
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        node = parse_txt_line(line.strip())
                        if node: nodes_in_file.append(node)
            raw_total += len(nodes_in_file)
            nodes = [p for p in nodes_in_file if isinstance(p, dict) and p.get('server') and p.get('type') and not any(k in str(p.get('name', '')).lower() for k in BAD_WORDS)]
            valid_total += len(nodes)
            for p in nodes:
                h = get_node_hash(p)
                if h not in registry:
                    registry[h] = {"first_seen": TODAY, "last_seen": TODAY, "success": 0, "fail": 0, "source_map": {}}
                registry[h].setdefault("source_map", {})
                registry[h]["last_seen"] = TODAY
                registry[h]["source_map"][file_path] = TODAY
                if len(registry[h]["source_map"]) > 10:
                    oldest = min(registry[h]["source_map"], key=registry[h]["source_map"].get)
                    del registry[h]["source_map"][oldest]
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    all_nodes.append(p)
        except Exception as e:
            print(f"[WARN] Failed to process {file_path}: {e}")
            continue

    registry = {k: v for k, v in registry.items() if v.get("last_seen", "") >= (datetime.now() - timedelta(days=MAX_IDLE_DAYS)).strftime("%Y-%m-%d")}
    save_registry(registry)

    final_nodes = [p for p in all_nodes if str(p.get('type', '')).lower() in EXPORT_TYPES]
    final_nodes.sort(key=lambda x: score_node(x, registry), reverse=True)
    final_nodes = fix_names(final_nodes[:500])
    
    # 统一使用 EXPORT_TYPES 进行分组逻辑判断
    group_fast = [p for p in final_nodes if str(p.get('type', '')).lower() in EXPORT_TYPES]
    
    proxy_groups = []
    if group_fast:
        proxy_groups.append({'name': '🚀 优选自动测速', 'type': 'url-test', 'proxies': [p.get('name') for p in group_fast[:100]], 'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50})
    proxy_groups.append({'name': '手动选择', 'type': 'select', 'proxies': (['🚀 优选自动测速'] if group_fast else []) + [p.get('name') for p in final_nodes]})
    
    config = {'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule', 'dns': {'enable': True, 'ipv6': False, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16', 'nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']}, 'proxies': final_nodes, 'proxy-groups': proxy_groups, 'rules': ['GEOIP,CN,DIRECT', 'GEOSITE,CN,DIRECT', 'MATCH,手动选择']}

    with open('merged_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print(f"\n--- 最终资产管理报告 ---")
    print(f"原始: {raw_total} | 过滤后: {valid_total} | 最终输出: {len(final_nodes)}")
    print(f"协议分布: {dict(Counter(p.get('type') for p in final_nodes))}")

if __name__ == "__main__":
    merge_yaml_nodes()
