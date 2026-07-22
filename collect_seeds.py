import re
import json
import base64
import ipaddress
import requests
from pathlib import Path
from datetime import datetime
import time
import random
from zoneinfo import ZoneInfo
# ====================== 配置 ======================
CONFIG_DIR = Path("config")
DATA_DIR = Path("data")
IP_FILE = Path("ip.txt")  # 保存到根目录
FRESH_LOG = DATA_DIR / "fresh_seeds_log.json"
SOURCES_FILE = Path("sources.txt")  # 数据源放在根目录的txt中
# 请求头伪装
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}
# ==================== 数据源 ====================
def load_sources():
    """从根目录sources.txt加载数据源"""
    if not SOURCES_FILE.exists():
        print(f"警告: {SOURCES_FILE} 不存在，使用默认空列表")
        return []
    return [line.strip() for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith('#')]

def try_base64_decode(text: str) -> str:
    """尝试将文本进行 Base64 解码"""
    clean_s = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    if len(clean_s) < 20:
        return text
    try:
        missing_padding = len(clean_s) % 4
        if missing_padding:
            clean_s += '=' * (4 - missing_padding)
        decoded = base64.b64decode(clean_s).decode('utf-8', errors='ignore')
        return text + "\n" + decoded
    except Exception:
        return text

def extract_ips_and_domains(text: str):
    """从文本中精准提取并清洗合法的 CIDR 网段"""
    found_items = set()
    # 1. 匹配标准 CIDR 格式（严格限制只接受 /24 到 /32 掩码，直接过滤 /1 等异常网段）
    cidr_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:2[4-9]|3[0-2])\b'
    for match in re.findall(cidr_pattern, text):
        try:
            net = ipaddress.ip_network(match, strict=False)
            # 过滤掉私有/保留网段
            if not net.is_private and not net.is_loopback and not net.is_reserved:
                found_items.add(str(net))
        except:
            continue
    # 2. 匹配独立 IPv4，自动转为规范的 /24 网段
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for match in re.findall(ipv4_pattern, text):
        try:
            ip_obj = ipaddress.ip_address(match)
            if not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_reserved:
                # 强制转换为标准的 /24 网络地址（主机位归零）
                net = ipaddress.ip_network(f"{match}/24", strict=False)
                found_items.add(str(net))
        except:
            continue
    return found_items

def collect_from_url(url: str):
    """从单个URL收集"""
    try:
        print(f"[+] 正在抓取: {url}")
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            print(f"    └─ 状态码异常: {resp.status_code}")
            return set()
        raw_text = resp.text
        processed_text = try_base64_decode(raw_text)
        found = extract_ips_and_domains(processed_text)
        print(f"    └─ 成功提取到 {len(found)} 个合法网段")
        return found
    except Exception as e:
        print(f"    └─ 抓取失败: {e}")
        return set()

def main():
    print(f"[{datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')}] 开始收集新鲜种子...\n")
    
    SOURCES = load_sources()
    
    all_new_items = set()
    for url in SOURCES:
        items = collect_from_url(url)
        all_new_items.update(items)
        time.sleep(random.uniform(1.0, 2.5))
    
    # 读取现有IP
    existing = set()
    if IP_FILE.exists():
        existing = {line.strip() for line in IP_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}
    
    really_new = all_new_items - existing
    combined = existing.union(all_new_items)
    
    # 写入文件（过滤空行）—— 保存到根目录
    clean_combined = sorted([x for x in combined if x])
    IP_FILE.write_text("\n".join(clean_combined), encoding="utf-8")
    
    # 日志记录
    log_entry = {
        "time": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
        "new_count": len(really_new),
        "total_now": len(clean_combined),
        "sources_checked": len(SOURCES)
    }
    try:
        if FRESH_LOG.exists():
            history = json.loads(FRESH_LOG.read_text(encoding="utf-8"))
        else:
            history = []
        history.append(log_entry)
        FRESH_LOG.write_text(json.dumps(history[-100:], indent=2, ensure_ascii=False), encoding="utf-8")
    except:
        pass
    
    print("\n" + "="*50)
    print(f"收集完成！")
    print(f"本次新增有效网段: {len(really_new)} 个")
    print(f"当前总种子数: {len(clean_combined)} 个")
    print(f"已更新 → {IP_FILE}")
    print("="*50)

if __name__ == "__main__":
    main()
