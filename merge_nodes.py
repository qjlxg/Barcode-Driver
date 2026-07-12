import yaml
import glob

def merge_yaml_nodes():
    merged_proxies = []
    seen_names = {}
    MAX_NODES = 500 

    for file_path in glob.glob("results/hash/*.yaml"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        if len(merged_proxies) >= MAX_NODES: break
                        
                        original_name = p.get('name', 'node')
                        
                        # 检查重名，如果已存在，则添加数字后缀，例如：美国节点_1, 美国节点_2
                        if original_name in seen_names:
                            seen_names[original_name] += 1
                            p['name'] = f"{original_name}_{seen_names[original_name]}"
                        else:
                            seen_names[original_name] = 0
                            p['name'] = original_name
                        
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
