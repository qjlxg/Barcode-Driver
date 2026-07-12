import yaml
import os
import glob

def merge_yaml_nodes():
    merged_proxies = []
    # 遍历所有 yaml 文件
    for file_path in glob.glob("results/hash/*.yaml"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'proxies' in data:
                    merged_proxies.extend(data['proxies'])
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    # 构建最终输出结构
    output = {
        'proxies': merged_proxies,
        'proxy-groups': [], # 根据需要可以留空或补充
        'rules': []
    }

    with open('merged_nodes.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(output, f, allow_unicode=True, default_flow_style=False)
    print(f"成功合并 {len(merged_proxies)} 个节点到 merged_nodes.yaml")

if __name__ == "__main__":
    merge_yaml_nodes()
