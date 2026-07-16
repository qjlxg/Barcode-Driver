import csv
import json
import ipaddress
from collections import defaultdict
from pathlib import Path
from datetime import datetime


# ============================================================
# 文件配置
# ============================================================

HISTORY_FILE = Path("seed_history.json")
IP_FILE = Path("ip.txt")
TARGETS_FILE = Path("targets.txt")
RESULTS_FILE = Path("scan_results.csv")


# ============================================================
# 淘汰策略
# ============================================================

# 从未有过任何产出的 /24
# 连续多少次“实际扫描但没有新增结果”后淘汰
MAX_INACTIVE_NEW = 7


# 曾经有过产出的 /24
# 连续多少次“实际扫描但没有新增结果”后淘汰
MAX_INACTIVE_OLD = 15


# ============================================================
# IP / CIDR 解析
# ============================================================

def get_cidr_key(target):
    """
    将以下格式统一转换为 /24：

        1.2.3.4
        1.2.3.4:80
        1.2.3.4:443
        1.2.3.0/24

    返回：

        1.2.3.0/24

    解析失败返回 None。
    """

    try:
        target = str(target).strip()

        if not target:
            return None

        # 已经是 CIDR
        if "/" in target:
            network = ipaddress.ip_network(
                target,
                strict=False
            )

            # 这里统一按 /24 作为种子判断单位
            if network.version == 4:
                ip = network.network_address
                network = ipaddress.ip_network(
                    f"{ip}/24",
                    strict=False
                )

            return str(network)

        # IPv4:PORT
        # 例如：
        # 1.2.3.4:443
        if ":" in target:
            target = target.rsplit(":", 1)[0]

        ip = ipaddress.ip_address(target)

        # 当前逻辑针对 IPv4 /24
        if ip.version != 4:
            return None

        network = ipaddress.ip_network(
            f"{ip}/24",
            strict=False
        )

        return str(network)

    except Exception:
        return None


# ============================================================
# 历史记录
# ============================================================

def load_history():
    """
    读取历史状态。

    如果文件不存在或损坏，则使用空历史。
    """

    if not HISTORY_FILE.exists():
        return {}

    try:
        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

    except Exception as e:
        print(
            f"[WARN] 无法读取 {HISTORY_FILE}: {e}"
        )

    return {}


def save_history(history):
    """
    保存历史状态。
    """

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            history,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# 读取本轮实际扫描的网段
# ============================================================

def read_scanned_cidrs():
    """
    读取 targets.txt。

    targets.txt 代表本轮真正交给后续扫描流程的目标。

    例如：

        1.2.3.0/24
        5.6.7.0/24

    最终统一成：

        {
            "1.2.3.0/24",
            "5.6.7.0/24"
        }
    """

    scanned_cidrs = set()

    if not TARGETS_FILE.exists():
        print(
            f"[WARN] {TARGETS_FILE} 不存在"
        )

        return scanned_cidrs

    try:

        with open(
            TARGETS_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                cidr = get_cidr_key(line)

                if cidr:
                    scanned_cidrs.add(cidr)

    except Exception as e:

        print(
            f"[WARN] 读取 {TARGETS_FILE} 失败: {e}"
        )

    return scanned_cidrs


# ============================================================
# 统计 scan_results.csv
# ============================================================

def read_result_counts():
    """
    统计 scan_results.csv 中每个 /24 当前累计拥有多少条结果。

    例如：

        1.2.3.0/24 -> 25
        5.6.7.0/24 -> 3

    这里的数量是累计结果数量。

    manage_seeds.py 会将：

        本次数量
        vs
        历史记录中的上次数量

    进行比较。

    如果：

        current_hits > last_total_hits

    则认为本轮产生了新增结果。
    """

    result_counts = defaultdict(int)

    if not RESULTS_FILE.exists():

        print(
            f"[WARN] {RESULTS_FILE} 不存在"
        )

        return result_counts

    try:

        with open(
            RESULTS_FILE,
            "r",
            encoding="utf-8",
            newline=""
        ) as f:

            reader = csv.reader(f)

            # 跳过表头
            next(reader, None)

            for row in reader:

                # 需要至少能够读取 row[2]
                if len(row) < 3:
                    continue

                cidr = get_cidr_key(row[2])

                if cidr:
                    result_counts[cidr] += 1

    except Exception as e:

        print(
            f"[WARN] 读取 {RESULTS_FILE} 失败: {e}"
        )

    return result_counts


# ============================================================
# 历史记录兼容与初始化
# ============================================================

def normalize_history_entry(entry):
    """
    兼容历史版本的 seed_history.json。

    确保每个网段至少拥有：

        last_total_hits
        no_hit_rounds
        has_historical_hit
    """

    if not isinstance(entry, dict):
        entry = {}

    return {
        "last_total_hits": int(
            entry.get(
                "last_total_hits",
                0
            )
        ),

        "no_hit_rounds": int(
            entry.get(
                "no_hit_rounds",
                0
            )
        ),

        "has_historical_hit": bool(
            entry.get(
                "has_historical_hit",
                False
            )
        )
    }


# ============================================================
# 核心管理逻辑
# ============================================================

def manage_seeds():

    print("=" * 60)
    print("        manage_seeds.py")
    print("        IP 种子生命周期管理")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. 读取历史
    # --------------------------------------------------------

    history = load_history()

    # 兼容历史格式
    for cidr in list(history.keys()):

        history[cidr] = normalize_history_entry(
            history[cidr]
        )

    # --------------------------------------------------------
    # 2. 读取本轮真正扫描过的 /24
    # --------------------------------------------------------

    scanned_cidrs = read_scanned_cidrs()

    print(
        f"[*] 本轮实际扫描网段: "
        f"{len(scanned_cidrs)}"
    )

    # --------------------------------------------------------
    # 3. 读取当前累计结果
    # --------------------------------------------------------

    current_results = read_result_counts()

    print(
        f"[*] 当前结果涉及网段: "
        f"{len(current_results)}"
    )

    # --------------------------------------------------------
    # 4. 更新本轮状态
    #
    # 只有 scanned_cidrs 中的网段才会更新：
    #
    # A. 本轮扫描 + 有新增
    #    no_hit_rounds = 0
    #
    # B. 本轮扫描 + 无新增
    #    no_hit_rounds += 1
    #
    # C. 本轮没有扫描
    #    完全不改变状态
    #
    # 这是核心逻辑。
    # --------------------------------------------------------

    new_result_cidrs = set()
    inactive_cidrs = set()

    for cidr in scanned_cidrs:

        # 如果是第一次见到这个网段
        if cidr not in history:

            history[cidr] = {
                "last_total_hits": 0,
                "no_hit_rounds": 0,
                "has_historical_hit": False
            }

        state = history[cidr]

        # 当前 scan_results.csv 中的累计结果数
        current_hits = current_results.get(
            cidr,
            0
        )

        # 上一次 manage_seeds.py 记录的结果数
        last_hits = state.get(
            "last_total_hits",
            0
        )

        # ----------------------------------------------------
        # 本轮出现新增结果
        # ----------------------------------------------------

        if current_hits > last_hits:

            state["no_hit_rounds"] = 0

            state["has_historical_hit"] = True

            new_result_cidrs.add(cidr)

            print(
                f"[+] 新增结果: "
                f"{cidr} "
                f"{last_hits} -> {current_hits}"
            )

        # ----------------------------------------------------
        # 本轮实际扫描，但没有新增结果
        # ----------------------------------------------------

        else:

            state["no_hit_rounds"] = (
                state.get(
                    "no_hit_rounds",
                    0
                ) + 1
            )

            inactive_cidrs.add(cidr)

        # 更新当前累计结果数量
        state["last_total_hits"] = current_hits

    # --------------------------------------------------------
    # 5. 判断哪些 /24 仍然保留
    #
    # 注意：
    #
    # 没有被本轮扫描的网段，
    # 不会增加 no_hit_rounds。
    #
    # 因此它们不会因为“没被扫描”
    # 而被误删。
    # --------------------------------------------------------

    alive_cidrs = set()

    pruned_cidrs = set()

    for cidr, state in history.items():

        no_hit_rounds = state.get(
            "no_hit_rounds",
            0
        )

        has_historical_hit = state.get(
            "has_historical_hit",
            False
        )

        # 曾经有过产出
        if has_historical_hit:

            if no_hit_rounds < MAX_INACTIVE_OLD:

                alive_cidrs.add(cidr)

            else:

                pruned_cidrs.add(cidr)

        # 从未有过产出
        else:

            if no_hit_rounds < MAX_INACTIVE_NEW:

                alive_cidrs.add(cidr)

            else:

                pruned_cidrs.add(cidr)

    # --------------------------------------------------------
    # 6. 清理 ip.txt
    #
    # ip.txt 保存的是原始 IP：
    #
    # 1.2.3.4
    # 1.2.3.5
    # 1.2.3.6
    #
    # 如果：
    #
    # 1.2.3.0/24
    #
    # 被淘汰，
    #
    # 那么这个 /24 下的所有 IP 都会被删除。
    # --------------------------------------------------------

    original_ips = []
    kept_ips = []
    removed_ips = []

    if IP_FILE.exists():

        with open(
            IP_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            original_ips = [
                line.strip()
                for line in f
                if line.strip()
            ]

        for ip in original_ips:

            cidr = get_cidr_key(ip)

            if cidr in alive_cidrs:

                kept_ips.append(ip)

            else:

                removed_ips.append(ip)

        # 去重，同时保持原始顺序
        kept_ips = list(
            dict.fromkeys(
                kept_ips
            )
        )

        with open(
            IP_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            if kept_ips:

                f.write(
                    "\n".join(
                        kept_ips
                    )
                )

                f.write("\n")

    else:

        print(
            f"[WARN] {IP_FILE} 不存在"
        )

    # --------------------------------------------------------
    # 7. 保存历史
    # --------------------------------------------------------

    save_history(history)

    # --------------------------------------------------------
    # 8. 输出统计
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("                管理完成")
    print("=" * 60)

    print(
        f"[*] 本轮扫描网段: "
        f"{len(scanned_cidrs)}"
    )

    print(
        f"[+] 本轮有新增结果: "
        f"{len(new_result_cidrs)}"
    )

    print(
        f"[-] 本轮扫描但无新增: "
        f"{len(inactive_cidrs)}"
    )

    print(
        f"[+] 当前保留网段: "
        f"{len(alive_cidrs)}"
    )

    print(
        f"[-] 已淘汰网段: "
        f"{len(pruned_cidrs)}"
    )

    print(
        f"[+] 保留 IP 数量: "
        f"{len(kept_ips)}"
    )

    print(
        f"[-] 删除 IP 数量: "
        f"{len(removed_ips)}"
    )

    print("=" * 60)


# ============================================================
# 程序入口
# ============================================================

if __name__ == "__main__":

    manage_seeds()