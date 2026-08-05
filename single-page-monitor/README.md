# SP 单页监控

这个小项目专门抓 Shopify/SP 站里的自定义产品单页，不参与原来的 Top20 旗舰评分逻辑。

## 判断原则

- 旗舰站仍按主监控里的 SimilarWeb 动态 Top20。
- 单页监控只负责找“被单独做成落地页的产品页”。
- 输出里会标记：
  - `top20_flagship`：这个站本来就在动态 Top20 旗舰里，同时发现了单页。
  - `core_candidate`：不在动态 Top20，但出现了 6 月或指定月份单页，适合单独沉淀为核心观察站。
  - `created_or_published_june`：强证据，产品创建或发布时间在目标月份。
  - `updated_june` / `sitemap_lastmod_june`：弱证据，可能是模板批量更新导致。

## 运行

```bash
node single-page-monitor/monitor.mjs --month 2026-06 --limit 200 --workers 6
```

常用参数：

- `--month 2026-06`：只关注这个月份的产品单页。
- `--limit 200`：扫描 Top200 站。
- `--workers 6`：并发浏览器数。
- `--max-json-pages 6`：每站最多翻几页 `/products.json`。
- `--fetch-mode auto`：默认先尝试轻量 HTTP；遇到 SP 站风控后自动切换到真实 Chrome。
- `--page-timeout 12000`：单个商品页最多等待 12 秒；超时标记为 `page_timeout` 后直接检查下一页，不会拖住整站。发现接口和 sitemap 仍使用较长超时。
- `--checkpoint-every 10`：每完成 10 站写一次完整检查点；扫描进度会单独逐站更新。
- `--min-request-interval-ms 900` / `--request-jitter-ms 500`：同一域名的请求起始间隔默认随机为 0.9–1.4 秒。
- `--max-consecutive-failures 3`：同站连续出现 429、403、挑战页或网络失败时自动熔断，跳过余下商品。
- `--cache-ttl-hours 18`：商品信号未变化时复用早晚两次扫描的分类结果，避免重复打开商品页。
- `--update-validation yes`：可选，把非 Top20 的单页核心候选同步进旗舰验证 JSON。默认不写，避免污染旗舰逻辑。

没有传 `--month` 时按 `Asia/Shanghai` 的当前月份运行，`config.json` 不再固定到历史月份。

## 每天自动跑

```bash
single-page-monitor/run_daily.sh
```

注意：macOS 的 launchd 后台进程可能没有 Desktop 目录权限，线上定时任务实际运行目录已迁到：

```bash
/Users/tonyaiuser/.spspy-single-page-monitor/single-page-monitor
```

改动代码后运行 `single-page-monitor/sync_deploy.sh` 同步线上目录。它会在
`~/.spspy-single-page-monitor/releases/` 中构建并验证不可变 release，最后原子
切换 `current`；launchd 继续使用原来的稳定入口
`single-page-monitor/run_daily.sh`，无需因代码更新重载 plist。`data/`、`logs/`
和 `reports/` 保留在稳定入口目录中，不会被复制、覆盖或放进 release。

`run_daily.sh` 默认会完成一整条链路：

- 扫描当前月份的 Top200 单页。
- 如果上月报告存在，把当前月份 + 上月合并成 `latest` 看板。
- 生成本月看板和 `latest` 看板。
- 发布到 GitHub Pages：`/single-page-monitor/latest.html` 和 `/single-page-monitor/<month>.html`。
- 发送钉钉图文消息，消息里包含看板截图和链接。

每天 21:05 的 FB 夜间验证链路还会触发一次完整扫描，但会标记为 `nightly_fb` 且关闭原始单页钉钉。两条链路共用同一个运行锁；重复启动会以退出码 75 安全退出，不会覆盖主任务状态或删除主任务的锁。

常用环境变量：

```bash
SP_SINGLE_PAGE_MONTH=2026-06 SP_SINGLE_PAGE_LIMIT=200 single-page-monitor/run_daily.sh
```

性能与诊断参数也可通过环境变量设置：`SP_SINGLE_PAGE_FETCH_MODE`、`SP_SINGLE_PAGE_TIMEOUT`、`SP_SINGLE_PAGE_PAGE_TIMEOUT`、`SP_SINGLE_PAGE_CHECKPOINT_EVERY`、`SP_SINGLE_PAGE_MIN_REQUEST_INTERVAL_MS`、`SP_SINGLE_PAGE_REQUEST_JITTER_MS`、`SP_SINGLE_PAGE_BACKOFF_BASE_MS`、`SP_SINGLE_PAGE_BACKOFF_MAX_MS`、`SP_SINGLE_PAGE_MAX_CONSECUTIVE_FAILURES`、`SP_SINGLE_PAGE_CACHE_TTL_HOURS`。

## 访问保护

扫描器不会用代理轮换、验证码绕过或伪造身份去规避网站防护。它会降低触发限流的概率，并在站点明确拒绝时主动停止：

- 每个站内只顺序请求，并加入随机间隔；不同域名仍可并行。
- 遇到 `Retry-After` 时按站点要求等待；429/403/挑战页采用指数退避，上限默认 60 秒。
- 服务端要求等待超过上限，或连续 3 次访问失败时，立即熔断该站，不再继续“硬扫”。
- 密码店、会员登录和付款访问门立即停止，并明确记录原因。
- 分类缓存位于 `data/classification_cache.json`，默认保留 18 小时且最多 50,000 条；商品更新时间或分类器版本变化后自动失效。

这些措施能明显降低被临时限流的概率，但任何外部网站都不能承诺“永不封禁”。

如果只想本地跑，不发钉钉：

```bash
SP_SINGLE_PAGE_SEND_DINGTALK=0 single-page-monitor/run_daily.sh
```

如果要交给 macOS launchd，每天 10:20 自动跑，可以把运行目录里的模板复制到 LaunchAgents 后加载：

```bash
cp /Users/tonyaiuser/.spspy-single-page-monitor/single-page-monitor/com.spspy.single-page-monitor.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.spspy.single-page-monitor.plist
```

## 输出

每次运行会生成：

- `reports/<month>/hits.csv`：命中的单页产品明细。
- `reports/<month>/sites.csv`：站点级结果。
- `reports/<month>/summary.md`：方便阅读的月报。
- `reports/<month>/new_hits.csv`：本项目首次发现的新单页。
- `reports/<month>/progress.json`：当前扫描进度，健康检查据此区分“运行较久”和“进度卡死”。
- `data/state.json`：历史状态，用来判断新增。
- `data/latest.json`：最近一次扫描摘要。

生成带产品图的看板：

```bash
node single-page-monitor/build_dashboard.mjs --month 2026-06 --workers 6
```

看板文件会输出到 `reports/<month>/dashboard.html`。默认按数据库里的首次发现单页时间排序，越新发现的单页越靠前；如果同款产品跨站重复，可以在看板里打开“隐藏同款重复”，只保留同款里最新发现的那条。

公开看板页面带有邮箱访问门：访问者需要输入已授权的公司邮箱才会显示内容。这个限制适用于普通访问场景；如果需要真正不可绕过的强认证，应把看板放到 Cloudflare Access、Vercel/Netlify 登录验证或其他服务端鉴权后面。

同时会镜像核心候选到 OpenClaw 工作区：

- `~/.openclaw/workspace/sp_single_page_core_candidates_<month>.json`
- `~/.openclaw/workspace/sp_top20_single_page_sites_<month>.txt`
- `~/.openclaw/workspace/sp_core_sites_single_page_<month>.txt`

## 诊断字段与健康检查

`sites.csv` 会记录 `scan_quality`、覆盖率、失败数、单页超时数、访问阻断数、缓存命中数、实际网络请求数、退避次数、熔断状态和失败原因。某一个商品页超时会被跳过并继续下一页；密码店、会员登录页、验证码/风控页不会再被误写成普通的“没有单页”，而会进入 `needs_rescan.csv`。

健康检查每 30 分钟运行一次：心跳超过 45 分钟、扫描进度超过 60 分钟不前进、任务失败或总运行超过 540 分钟才报警；恢复后会补发一次恢复通知。

运行测试：

```bash
cd single-page-monitor
npm test
```

`sync_deploy.sh` 会先运行测试和语法检查，在独立 staging release 中安装依赖并再次运行该 release 自己的 `npm test`。部署、稳定入口和源码入口默认都锁定同一个持久化 `data/` 目录 inode；这个业务目录不会在部署时被替换。`data/run_daily.lock` 只是兼容旧 runner 的固定入口。锁描述符跨 `exec` 保持，进程退出或崩溃后由内核释放，忙时统一返回 75，不依赖 PID 或残留锁清理。兼容目录带固定 `pid=0`，因此首次迁移时旧版 runner 也会安全退让；即使兼容目录被重命名或重建，也不会产生第二个锁 owner。锁定前会拒绝 symlink 或在获取期间发生 inode 变化的 `data/` 目录。

所有 release 文件和目录、release rename、`current` 切换及稳定入口替换都会执行 `fsync`。`current` 是最后一个提交点；此前失败会恢复原入口，进入提交后会屏蔽中断信号，切换成功只返回 0。首次迁移还会保留一份旧 health checker，但只有部署阶段门存在且稳定运行目录的 phase 锁确实被部署进程持有时才能使用；提交成功后 fallback 和阶段门会一起持久删除，部署进程被强杀后 phase 锁也由内核释放，因此缺失 `current` 会按失败关闭。稳定入口会逐层拒绝 release 路径中的目录 symlink，再把 runner/checker 固定为选中 release 内的绝对路径。运行时的 `data/`、`logs/`、`reports/` 和 `.pages/` 全部位于 release 外部。
