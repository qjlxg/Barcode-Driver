import yaml
import glob
import hashlib
import json
import os
from datetime import datetime, timedelta

REGISTRY_FILE = 'node_registry.json'
MAX_IDLE_DAYS = 30
ALLOWED_TYPES = {'vless', 'hysteria', 'hysteria2', 'tuic', 'anytls'}
TODAY = datetime.now().strftime("%Y-%m-%d")

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_registry(registry):
    with open(REGISTRY_FILE, 'w') as f: json.dump(registry, f, indent=2)

def get_node_hash(p):
    node_copy = p.copy()
    for k in ['name', 'skip-cert-verify']:
        node_copy.pop(k, None)
    return hashlib.md5(json.dumps(node_copy, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()

def score_node(p, registry):
    h = get_node_hash(p)
    hist = registry.get(h, {})
    score = 0
    
    # 评分逻辑
    try:
        first = datetime.strptime(hist.get('first_seen', TODAY), "%Y-%m-%d")
        days_alive = max((datetime.now() - first).days + 1, 1)
        score += min(days_alive, 5)
    except: score += 1
    
    s, f = hist.get('success', 0), hist.get('fail', 0)
    if s + f > 0: score += (s / (s + f)) * 5
    
    score += min(len(hist.get("source_map", {})), 2)
    
    t = str(p.get('type', '')).lower()
    score += {'hysteria2': 3, 'hysteria': 3, 'tuic': 3, 'vless': 3, 'anytls': 2}.get(t, 0)
    
    name = str(p.get('name', '')).lower()
    if any(x in name for x in ['jp', 'japan', '日本', 'tokyo']): score += 2
    elif any(x in name for x in ['sg', 'singapore', '新加坡']): score += 1
    
    if p.get('reality-opts') or p.get('reality'): score += 3
    elif p.get('tls'): score += 1
    
    if t in ['hysteria2', 'hysteria', 'tuic'] and str(p.get('udp', '')).lower() == 'true':
        score += 1
    port = str(p.get('port', ''))
    if port == '443': score += 1
    elif port == '8443': score += 0.5
    
    return score

def merge_yaml_nodes():
    registry = load_registry()
    all_nodes, seen_hashes = [], set()
    raw_total, valid_total = 0, 0
    
    files = glob.glob("results/hash/*.yaml")
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if not data or 'proxies' not in data: continue
                raw_total += len(data['proxies'])
                
                nodes = [p for p in data['proxies'] if isinstance(p, dict) and p.get('server') 
                         and str(p.get('type', '')).lower() in ALLOWED_TYPES
                         and not any(k in str(p.get('name', '')).lower() for k in ['cf', '优选','节点'])]
                
                # 预处理：确保所有节点都有 name 字段
                for i, p in enumerate(nodes):
                    if 'name' not in p or not p['name']:
                        p['name'] = f"node-{file_path.split('/')[-1]}-{i}"
                
                valid_total += len(nodes)
                for p in nodes:
                    h = get_node_hash(p)
                    if h not in registry:
                        registry[h] = {"first_seen": TODAY, "last_seen": TODAY, "success": 0, "fail": 0, "source_map": {file_path: TODAY}}
                    else:
                        registry[h]["last_seen"] = TODAY
                        registry[h].setdefault("source_map", {})[file_path] = TODAY
                    
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        all_nodes.append(p)
        except: continue

    registry = {k: v for k, v in registry.items() if v.get("last_seen", "") >= (datetime.now() - timedelta(days=MAX_IDLE_DAYS)).strftime("%Y-%m-%d")}
    save_registry(registry)

    all_nodes.sort(key=lambda x: score_node(x, registry), reverse=True)
    merged_proxies = all_nodes[:300]
    
    # 最终输出配置
    config = {
        'port': 7890, 'socks-port': 7891, 'allow-lan': True, 'mode': 'rule',
        'dns': {
            'enable': True, 'ipv6': False, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
        },
        'proxies': merged_proxies,
        'proxy-groups': [
            {'name': '🚀 优选自动测速', 'type': 'url-test', 'proxies': [p.get('name') for p in merged_proxies[:80]], 'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
            {'name': '手动选择', 'type': 'select', 'proxies': ['🚀 优选自动测速'] + [p.get('name') for p in merged_proxies]}
        ],
        'rules': ['GEOIP,CN,DIRECT', 'GEOSITE,CN,DIRECT', 'MATCH,手动选择']
    }

    with open('merged_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    
    print(f"\n--- 最终资产管理报告 ---")
    print(f"原始: {raw_total} | 过滤后: {valid_total} | 最终输出: {len(merged_proxies)}")

if __name__ == "__main__":
    merge_yaml_nodes()
