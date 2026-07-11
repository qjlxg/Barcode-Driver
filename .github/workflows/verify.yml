name: 资产深度验证与报告
on:
  workflow_dispatch:

jobs:
  verify_job:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: 安装依赖
        run: pip install aiohttp PyYAML

      - name: 执行深度验证
        run: |
          # 运行验证脚本
          python verify.py
          
          # 创建一个占位报告，防止后面指令因文件不存在报错
          echo "ip,port,status" > verify_report.csv
          
          # 只有当目录存在且不为空时，才提取数据
          if [ -d "temp_hash" ] && [ "$(ls -A temp_hash/)" ]; then
            ls temp_hash/ | sed 's/\.yaml//' | awk -F'_' '{print $1","$2",found"}' >> verify_report.csv
            echo "[*] 发现资产，已写入报告。"
          else
            echo "[*] 未发现任何资产，报告为空。"
          fi

      - name: 提交验证报告
        run: |
          git config --global user.name 'github-actions[bot]'
          git config --global user.email 'github-actions[bot]@users.noreply.github.com'
          
          # 检查文件是否有变更
          if [[ -n $(git status -s) ]]; then
            git add verify_report.csv
            git commit -m "Report: Add verify_report.csv"
            git push origin main
          else
            echo "没有新增资产，跳过提交。"
          fi
