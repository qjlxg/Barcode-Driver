import yaml
import glob

def merge_yaml_nodes():
    merged_proxies = []
    seen_names = {}
    MAX_NODES = 500 

    # 1. 读取所有节点文件
    for file_path in glob.glob("results/hash/*.yaml"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        if len(merged_proxies) >= MAX_NODES: break

                        original_name = p.get('name', 'node')

                        # 处理重名
                        if original_name in seen_names:
                            seen_names[original_name] += 1
                            p['name'] = f"{original_name}_{seen_names[original_name]}"
                        else:
                            seen_names[original_name] = 0
                            p['name'] = original_name

                        merged_proxies.append(p)
        except: continue

    # 2. 构建配置
    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule', # 这里定义为规则模式
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
        # 核心修改：添加分流规则
        'rules': [
            'GEOIP,CN,DIRECT',          # 所有中国大陆的IP地址走直连
            'GEOSITE,CN,DIRECT',        # 所有中国大陆的域名走直连
            'DOMAIN-SUFFIX,douyin.com,DIRECT', # 抖音及其相关服务
            'DOMAIN-SUFFIX,amemv.com,DIRECT',
            'MATCH,手动选择'            # 其他所有流量走你选择的节点
        ]
    }

    # 3. 写入文件
    with open('merged_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    
    print("配置文件已生成: merged_nodes.yaml")

if __name__ == "__main__":
    merge_yaml_nodes()
