# SP 集团选品看板 v2.0

## 快速打开

直接双击 `sp_picker_dashboard.html`，或在终端运行：

```bash
open /Users/tonyaiuser/Desktop/spspy/sp_picker_dashboard.html
```

无需服务器，纯静态 HTML，直接在浏览器中运行。

---

## 当前数据流

每日任务入口：

```bash
/Users/tonyaiuser/Desktop/spspy/scripts/run_daily.sh
```

执行顺序：
1. 从 `~/.openclaw/workspace/sp_hotlist_*.json` 同步 SP 热榜（由 `skills/sp-monitor/run.py --send` 生成）
2. 预抓取商品图片并写入 `data/images.json`
3. 合并最近 3 天热榜，生成 `sp_picker_dashboard.html`
4. 更新 `data/history.json` 趋势缓存
5. 自动提交并推送到 GitHub

定时任务：
- `com.spspy.daily`：每天 12:30 自动更新看板
- `com.spspy.similarweb`：每 30 分钟跑一次 SimilarWeb 扫描

---

## 数据来源与规则

最近 3 天的 `sp_hotlist_YYYY-MM-DD.json` 会被合并，按 `handle` 去重，保留最新快照并记录峰值分，输出 **Top 100** 商品。

上游晨报采用“只发变化”策略：钉钉正文只推首次发现、铺货站点增长、FB/LP 新信号、新进 Top 榜或分数显著上升的商品；稳定老品不再每天重复推。

```text
上游 score = 上架新鲜度衰减后的站点分 + 旗舰站权重 + FB命中 + LP命中 + 扩散速度 - 老化惩罚
看板 score = 上游 score + 首次出现/站点增长/投放信号加成 - 稳定老品降权
```

字段说明：
- `sites_count`：该商品在多少个 SP 站点同时上架
- `flagship_count`：命中旗舰站数量
- `sample_url`：代表性商品页
- `trend`：近 14 天铺货站点数历史
- `is_new`：是否为近期上架或近 3 天首次进入监控
- `delta_1d` / `spread_delta`：铺货扩散速度
- `fb_hit_count` / `is_lp`：旗舰站 FB 投放和 LP 落地页信号

---

## 页面功能

- **Top 100 商品卡片**，按评分降序展示
- **变化优先排序**，新发现 / 扩散中 / 投放信号优先于稳定老品
- **品类筛选**
- **趋势数据**，显示近几天铺货变化
- **新品标记**
- **商品图片**，优先使用预抓取的 og:image / Shopify API 图
- **真实货币符号**，按站点实际货币显示价格（£ / $ / € 等）

---

## 关键文件

```text
sp_picker_dashboard.html         主页面
sp_picker_dashboard_README.md    项目说明
scripts/run_daily.sh             每日总调度
scripts/sync_openclaw.py         同步 OpenClaw 热榜
scripts/fetch_images.py          图片抓取与缓存
scripts/build_dashboard.py       看板生成
data/images.json                 图片缓存
data/history.json                趋势缓存
logs/daily_YYYY-MM-DD.log        每日日志
logs/daily_error_YYYY-MM-DD.log  每日错误日志
```

---

## 已做的工程优化

- 日志按天拆分，排查更清楚
- 图片抓取失败会记录失败类型
- 对明确 404 的商品延长重试周期，减少无效请求
- 钉钉日报只推变化，避免每天重复推同一批稳定商品

---

## 后续可继续优化

- 抓图失败类型做更细粒度统计报表
- 页面里直接展示趋势小图
- 增加人工备注 / 导出 CSV
- 补一份部署与恢复说明
