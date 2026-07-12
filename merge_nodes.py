import yaml
import glob
import hashlib

def merge_yaml_nodes():
    merged_proxies = []
    seen_nodes = set()
    MAX_NODES = 500 

    for file_path in glob.glob("results/hash/*.yaml"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        if len(merged_proxies) >= MAX_NODES: break
                        
                        # 使用 name 和 server/ip 作为唯一标识去重
                        name = p.get('name', 'node')
                        server = p.get('server', '')
                        node_id = (name, server)
                        
                        if node_id in seen_nodes:
                            continue
                        seen_nodes.add(node_id)
                        
                        # 生成唯一且具备辨识度的名称
                        suffix = hashlib.md5(f"{name}{server}".encode()).hexdigest()[:4]
                        p['name'] = f"{name}_{suffix}"
                        
                        merged_proxies.append(p)
        except: continue

    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'dns': {
            'enable': True,
            'ipv6': False,
            'enhanced-mode': 'fake-ip',
            'nameserver': ['223.5.5.5', '119.29.29.29', '180.76.76.76']
        },
        'proxies': merged_proxies,
        'proxy-groups': [
            {
                'name': '自动选择',
                'type': 'url-test',
                'proxies': [p['name'] for p in merged_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 900
            },
            {
                'name': '手动选择',
                'type': 'select',
                'proxies': ['自动选择'] + [p['name'] for p in merged_proxies]
            }
        ],
        'rules': ['MATCH,手动选择']
    }

    with open('merged_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

if __name__ == "__main__":
    merge_yaml_nodes()
