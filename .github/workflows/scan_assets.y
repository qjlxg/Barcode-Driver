name: 1. scan_assets

on:
  workflow_dispatch:
  push:
    branches:
      - main
    paths:
      - '.github/workflows/scan_assets.yml'
      - 'scan_assets.py'
      - 'targets.txt'
      - 'ports.txt'

jobs:
  scanner:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: 检出代码
        uses: actions/checkout@v4
      
      - name: 设置 Python 环境
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: 执行端口扫描
        run: python3 scan_assets.py

      - name: 提交结果到仓库
        run: |
          git config --global user.name 'github-actions[bot]'
          git config --global user.email 'github-actions[bot]@users.noreply.github.com'
          
          # 检查是否有文件变更
          if [[ -n $(git status -s alive_ips.txt) ]]; then
            git add alive_ips.txt
            git commit -m "Update: Assets $(date +'%Y-%m-%d %H:%M') [skip ci]"
            git push origin main
          else
            echo "[-] alive_ips.txt 无变化，无需提交。"
          fi
