name: 3. 资产精炼 (Refine)

on:
  workflow_dispatch:
  push:
    branches:
      - main
    paths:
      - '.github/workflows/refine.yml'
      - 'refine_assets.py'

jobs:
  refine_job:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      
      - name: 安装依赖
        run: pip install aiohttp
      
      - name: 运行精炼脚本
        run: python3 refine_assets.py
          
      - name: 提交精炼结果
        run: |
          git config --global user.name 'github-actions[bot]'
          git config --global user.email 'github-actions[bot]@users.noreply.github.com'
          
          if [[ -n $(git status -s refined_ips.txt) ]]; then
            git add refined_ips.txt
            git commit -m "Update: Refined asset list $(date +'%Y-%m-%d') [skip ci]"
            git pull origin main --rebase
            git push origin main
          else
            echo "[-] refined_ips.txt 无变化。"
          fi
