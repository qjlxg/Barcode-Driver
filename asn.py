import requests
import ipaddress
import re
import json
import time
import random
from datetime import datetime
from pathlib import Path

# ================= 配置区域 =================
BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
ASN_SEED_FILE = CONFIG_DIR / "asn_seed.txt"
IP_FILE = BASE_DIR / "ip.txt"                  # 最终运行结果保存到根目录下 ip.txt
ASN_HISTORY_FILE = CONFIG_DIR / "asn_history.json"

FETCH_DELAY = (3, 7)         # 随机延迟范围（秒），防止被 HE.net 封禁
BATCH_SIZE = 25              # 每次从当前 ASN 中取出的网段数量

# 扩展后的 CDN 及 基础运营商 ASN 黑名单
EXCLUDE_ASNS = {
    "AS13335", "AS20940", "AS16625", "AS22822", "AS36183", "AS54113",
    "AS11878", "AS16509", "AS14618", "AS15169", "AS396983", "AS8075",
    "AS8068", "AS15133", "AS3356", "AS1299", "AS174"
}

# ================= 工具函数 =================

def setup_env():
    """初始化环境"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not ASN_SEED_FILE.exists():
        ASN_SEED_FILE.write_text("# 在此输入ASN，每行一个，如：AS12345\n", encoding="utf-8")
        print(f"[*] 已创建种子文件: {ASN_SEED_FILE}，请填入 ASN 后重新运行。")
        return False
    return True

def load_history():
    if ASN_HISTORY_FILE.exists():
        try:
            return json.loads(ASN_HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_history(history_data):
    ASN_HISTORY_FILE.write_text(json.dumps(history_data, indent=2, ensure_ascii=False), encoding="utf-8")

def get_prefixes_from_he(asn):
    """从 HE.net 获取前缀，带重试机制"""
    asn_digit = asn.upper().replace("AS", "")
    url = f"https://bgp.he.net/AS{asn_digit}#_prefixes"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Referer": "https://bgp.he.net/",
        "Upgrade-Insecure-Requests": "1"
    }

    try:
        time.sleep(random.uniform(*FETCH_DELAY))
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 404:
            print(f"    [!] ASN {asn} 不存在 (404)")
            return set()
        if "maintaining this site" in r.text or r.status_code == 429:
            print(f"    [!] 触发 HE.net 反爬虫限制，请更换 IP 或稍后再试")
            return set()

        prefixes = set(re.findall(r'/net/(\d+\.\d+\.\d+\.\d+/\d+)', r.text))
        return prefixes
    except Exception as e:
        print(f"    [!] 网络请求失败: {e}")
        return set()

def process_to_24(prefix_set):
    """将获取到的网段统一转换为 /24"""
    results = set()
    for p in prefix_set:
        try:
            net = ipaddress.ip_network(p, strict=False)
            if not net.is_global: continue

            if net.prefixlen < 24:
                if net.prefixlen < 16:
                    continue
                for subnet in net.subnets(new_prefix=24):
                    results.add(str(subnet))
            elif net.prefixlen == 24:
                results.add(str(net))
            else:
                results.add(str(net.supernet(new_prefix=24)))
        except:
            continue
    return results

# ================= 主程序 =================

def collect():
    if not setup_env(): return

    history = load_history()
    progress = history.get("_progress", {"asn_index": 0, "cidr_index": 0})
    asn_index = progress.get("asn_index", 0)
    cidr_index = progress.get("cidr_index", 0)

    # 获取待处理 ASN 种子
    raw_asns = [
        l.strip().upper()
        for l in ASN_SEED_FILE.read_text(encoding="utf-8").splitlines()
        if re.match(r"^AS\d+$", l.strip().upper())
    ]

    total_asns = len(raw_asns)
    if total_asns == 0:
        print("[!] asn_seed.txt 中未发现有效的 ASN")
        return

    # 如果所有 ASN 都已经消费完毕
    if asn_index >= total_asns:
        print("[*] asn_seed.txt 中的所有 ASN 网段已全部取完！请加入新的 ASN 到 seed 文件中。")
        IP_FILE.write_text("", encoding="utf-8")
        return

    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    current_asn = raw_asns[asn_index]

    if current_asn in EXCLUDE_ASNS:
        print(f"[*] 跳过名单内 ASN: {current_asn}")
        history["_progress"] = {"asn_index": asn_index + 1, "cidr_index": 0}
        save_history(history)
        return

    print(f"\n[*] 当前处理 ASN [{asn_index + 1}/{total_asns}]: {current_asn}")

    # 检查历史记录里是否已经完整缓存过该 ASN 的网段
    asn_record = history.get(current_asn, {})
    cached_cidrs = asn_record.get("all_cidrs", [])

    if not cached_cidrs:
        print(f"    -> 正在从 HE.net 抓取 {current_asn} 的所有网段...")
        raw_prefixes = get_prefixes_from_he(current_asn)
        if not raw_prefixes:
            print(f"    [!] 未能获取到前缀，跳过该 ASN")
            history["_progress"] = {"asn_index": asn_index + 1, "cidr_index": 0}
            save_history(history)
            return

        processed_cidrs = sorted(list(process_to_24(raw_prefixes)))
        cached_cidrs = processed_cidrs
        
        # 缓存该 ASN 的全量网段
        history[current_asn] = {
            "last_scan": current_time_str,
            "total_count": len(cached_cidrs),
            "all_cidrs": cached_cidrs
        }
        print(f"    -> 成功获取并缓存 {current_asn} 的全量网段共 {len(cached_cidrs)} 个")
    else:
        print(f"    -> 使用本地缓存的 {current_asn} 网段，总量: {len(cached_cidrs)}")

    total_cidrs_in_asn = len(cached_cidrs)

    if cidr_index >= total_cidrs_in_asn:
        print(f"    [!] ASN {current_asn} 的所有网段已全部取完，准备切入下一个 ASN")
        history["_progress"] = {"asn_index": asn_index + 1, "cidr_index": 0}
        save_history(history)
        return

    # 从当前 cidr_index 开始截取 25 个
    end_cidr_index = min(cidr_index + BATCH_SIZE, total_cidrs_in_asn)
    batch_cidrs = cached_cidrs[cidr_index:end_cidr_index]

    print(f"    -> 本次截取范围: 索引 {cidr_index} 到 {end_cidr_index} (共 {len(batch_cidrs)} 个网段)")

    # 写入根目录下的 ip.txt
    IP_FILE.write_text("\n".join(batch_cidrs), encoding="utf-8")
    print(f"    [+] 已成功将 {len(batch_cidrs)} 个网段保存到根目录 ip.txt 中")

    # 更新进度
    next_cidr_index = end_cidr_index
    next_asn_index = asn_index

    if next_cidr_index >= total_cidrs_in_asn:
        print(f"    [*] ASN {current_asn} 的所有网段已取完，下次将自动切换到下一个 ASN")
        next_asn_index += 1
        next_cidr_index = 0

    history["_progress"] = {
        "asn_index": next_asn_index,
        "cidr_index": next_cidr_index
    }
    save_history(history)
    print(f"[*] 本次运行结束。下次运行进度指针 -> ASN索引: {next_asn_index}, 网段索引: {next_cidr_index}")
