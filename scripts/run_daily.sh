#!/bin/bash
# run_daily.sh - 每日编排脚本
# 调用顺序: 从 openclaw 同步数据 → 图片抓取 → 看板生成 → 清理旧数据
set -euo pipefail

export PATH="/opt/homebrew/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

OPENCLAW_DIR="$HOME/.openclaw/workspace"
LOG_DIR="$PROJECT_DIR/logs"
TODAY="$(date '+%Y-%m-%d')"
RUN_LOG="$LOG_DIR/daily_${TODAY}.log"
ERR_LOG="$LOG_DIR/daily_error_${TODAY}.log"

mkdir -p "$LOG_DIR"
mkdir -p reports/dingtalk
exec > >(tee -a "$RUN_LOG")
exec 2> >(tee -a "$ERR_LOG" >&2)

echo "========================================="
echo "SP 选品看板 每日更新"
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "项目目录: $PROJECT_DIR"
echo "日志文件: $RUN_LOG"
echo "错误日志: $ERR_LOG"
echo "========================================="

# 确认 Python3 可用
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

# 确认数据目录存在
if [ ! -d "data/daily" ]; then
    echo "ERROR: data/daily directory not found"
    exit 1
fi

# Step 0: 从 openclaw workspace 同步并转换数据
echo ""
echo "--- Step 0: 从 openclaw 同步数据 ---"
python3 scripts/sync_openclaw.py

# 检查是否有数据文件
DATA_COUNT=$(ls data/daily/sp_hotlist_*.json 2>/dev/null | wc -l | tr -d ' ')
if [ "$DATA_COUNT" = "0" ]; then
    echo "ERROR: No hotlist data files found in data/daily/"
    exit 1
fi
echo "Found $DATA_COUNT daily data files"

# Step 1: 抓取商品图片
echo ""
echo "--- Step 1: 抓取商品图片 ---"
python3 scripts/fetch_images.py

# Step 2: 生成看板 HTML
echo ""
echo "--- Step 2: 生成看板 HTML ---"
python3 scripts/build_dashboard.py
python3 scripts/build_top150_dashboard.py

# Step 3: 清理 30 天前的旧数据
echo ""
echo "--- Step 3: 清理旧数据 ---"
OLD_COUNT=$(find data/daily -name "sp_hotlist_*.json" -mtime +30 2>/dev/null | wc -l | tr -d ' ')
if [ "$OLD_COUNT" -gt "0" ]; then
    find data/daily -name "sp_hotlist_*.json" -mtime +30 -delete
    echo "Cleaned $OLD_COUNT old data files"
else
    echo "No old data files to clean"
fi

OLD_REPORT_COUNT=$(find reports/dingtalk -name "sp_report_*.png" -mtime +30 2>/dev/null | wc -l | tr -d ' ')
if [ "$OLD_REPORT_COUNT" -gt "0" ]; then
    find reports/dingtalk -name "sp_report_*.png" -mtime +30 -delete
    echo "Cleaned $OLD_REPORT_COUNT old DingTalk report images"
else
    echo "No old DingTalk report images to clean"
fi

# Step 4: 推送到 GitHub
echo ""
echo "--- Step 4: 推送到 GitHub ---"
if ! git config --get user.name >/dev/null; then
    git config user.name "tonyaiuser"
fi
if ! git config --get user.email >/dev/null; then
    git config user.email "tonyaiuser@tonyaiuserdeMac-mini.local"
fi
git add -A sp_picker_dashboard.html sp_top150_dashboard.html reports/dingtalk
if git diff --cached --quiet; then
    echo "No changes to push"
else
    git commit -m "daily update $(date '+%Y-%m-%d')"
    git push origin main
    echo "Pushed to GitHub"
fi

echo ""
echo "========================================="
echo "Done! Dashboard updated."
echo "========================================="
