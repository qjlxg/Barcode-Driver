import yaml
import glob
import re

def get_filtered_nodes(proxies):
    # 正则：涵盖地区变种 (日本/美国及其缩写)
    reg_regex = re.compile(r"(?i)(日本|JP|Japan|Tokyo|Osaka|美国|US|UnitedStates|USA|LA|NY|NewYork|California)")
    # 正则：涵盖协议变种 (高性能协议及缩写)
    proto_regex = re.compile(r"(?i)(hy|hysteria|h2|vless|vmess|trojan|ss|ssr|shadowsocks|anytls)")
    # 正则：过滤垃圾信息
    exclude_regex = re.compile(r"(?i)(过期|失效|测试|保留)")
    
    filtered = []
    for p in proxies:
        name = p.get('name', '')
        # 必须同时匹配地区和协议，且不能包含垃圾词
        if reg_regex.search(name) and proto_regex.search(name) and not exclude_regex.search(name):
            filtered.append(p)
    return filtered

def merge_yaml_nodes():
    all_nodes = []
    seen_names = {}

    # 1. 读取并筛选节点
    for file_path in glob.glob("results/hash/*.yaml"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'proxies' in data:
                    nodes = get_filtered_nodes(data['proxies'])
                    for p in nodes:
                        # 防重名处理
                        original_name = p.get('name', 'node')
                        if original_name in seen_names:
                            seen_names[original_name] += 1
                            p['name'] = f"{original_name}_{seen_names[original_name]}"
                        else:
                            seen_names[original_name] = 0
                            p['name'] = original_name
                        all_nodes.append(p)
        except: continue

    # 2. 确定节点池 (最多500个)
    merged_proxies = all_nodes[:500]
    # 优选测速池 (前50个，防止测速卡死)
    fast_proxies = merged_proxies[:50]

    # 3. 构建配置
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
                'name': '🚀 优选自动测速',
                'type': 'url-test',
                'proxies': [p['name'] for p in fast_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50
            },
            {
                'name': '手动选择',
                'type': 'select',
                'proxies': ['🚀 优选自动测速'] + [p['name'] for p in merged_proxies]
            }
        ],
        'rules': [
            'GEOIP,CN,DIRECT',
            'GEOSITE,CN,DIRECT',
            'MATCH,手动选择'
        ]
    }

    # 4. 写入文件
    with open('merged_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    
    print(f"配置文件已生成！成功抓取节点: {len(merged_proxies)} 个。")

if __name__ == "__main__":
    merge_yaml_nodes()
