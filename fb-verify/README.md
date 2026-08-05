# FB 广告库验证

对单页监控（`com.spspy.single-page-monitor`，每天 08:30 启动，耗时随当月候选量变化）发现、但尚未
经过 FB 验证的单页产品，做一轮 Facebook 广告库验证（是否真的有人在投这款产品的广告）+ 抓产品主图，
更新月累计看板，发布到 GitHub Pages。

## 判断原则

- 单页监控只负责"发现被单独做成落地页的产品"，本项目负责回答下一个问题："这个产品有没有
  在 Facebook 广告库里查到真实投放痕迹"。
- v1 只验证**新出现且尚未处理的产品组**，不复查已经验证过的老组——月初会读取上月成员与查询词，
  精确 `domain|handle` 重复项直接跳过；同款新增站点复用上月结果，不重复请求 FB。
- 同款产品（标题清洗后查询词归一化相同）会被合并成一组，只查一次，即使它同时被好几个
  监控站跟卖。
- 纯脚本（python3 + node + Playwright），launchd 定时调度，不依赖任何 AI/LLM。
- 不改单页监控的任何文件；首选只读其持久事件流 `data/events.jsonl`，`reports/<月份>/new_hits.csv`
  仅在事件流缺失时作为兼容兜底。这样晚间完整扫描产生的新单页不会被次日 CSV 覆盖而漏掉。
- 当天流程整体成功且本轮新验证组里确实有 Facebook 相关活跃投放，发一条独立的钉钉消息告知；
  0 个确认匹配不发（避免打扰），
  和单页监控"没有新内容不重复发"的习惯一致。推送逻辑跟单页监控的推送代码完全独立，只是
  复用同一份凭证读取方式（见下文"钉钉推送"）。

## 目录结构

```
fb-verify/
  run_daily_fb_verify.sh   编排入口，launchd 每天调用它
  run_nightly_single_page_fb_verify.sh  每晚完整单页扫描后触发 FB 增量验证
  sync_deploy.sh          在独立 stage 校验代码并原子切换隐藏目录的 immutable release
  deployment_entrypoint.sh  launchd 稳定入口；固定本次运行的 release 与持久 data 路径
  com.spspy.single-page-fb-nightly.plist  每晚 21:05 的 launchd 模板
  scripts/
    query_utils.py           查询词清洗规则（去 emoji/促销词/价格，截取 3-6 词核心短语）
    ingest_new_hits.py        读持久 events.jsonl 中当月未处理的新命中（月初接住前一日事件；CSV 兜底），各建一个待验证组
    merge_duplicate_query_groups.py  按归一化查询词合并同款组（新并老 / 新并新）
    fb_product_verify.mjs     单次查询：打 FB 广告库 exact_phrase 搜索，抓一页结果
    run_verify_new_groups.mjs 批量 runner：只查未验证过的组，限速 8-14s，单日上限 40 组，
                               连续 5 组空结果熔断退出（明天自动续跑剩余的）
    fetch_new_images.py       抓产品主图（Shopify JSON 优先，og:image 兜底），已缓存自动跳过
    build_fb_verify_page.py   生成月累计看板 fb_verify_dashboard.html（自包含，无 CDN 依赖）
    publish_fb_pages.py       隔离的 Git Pages 发布事务：锁、commit/lease push 与远端字节核验
    compute_verify_stats.py   从今天验证过的 group_id 里算🔥新起投/多站跨投数量，供钉钉消息用
    notify_dingtalk.py        独立钉钉推送：只读复用单页监控同一套 webhook/secret 获取方式
  ~/.spspy-fb-verify/fb-verify/  launchd 实际运行目录（代码 + 实时 data，避开 Desktop TCC）
  data/<YYYY-MM>/             月度状态，月滚动自动新建
    unique_products.json      去重后的产品组（query / members / 是否已验证）
    product_verify_full.json  FB 验证结果，按 group_id 索引
    product_images.json       产品主图缓存，domain|handle -> image_url
    fb_verify_dashboard.html  当月看板（发布时会被拷到 babata-board 仓库根目录）
  data/run_daily.lock         daily/nightly 共用的兼容锁入口（owner 目录内持有内核锁）
  data/last_attempt_date.txt  本次流水线尝试日期（仅审计，不影响重试）
  data/last_attempt_id.txt    最近一次实际执行的唯一 run id
  data/pipeline_status.json   当前 run 的 in_progress / partial / failed / succeeded 状态
  data/last_published_success.txt  仅在验证队列清空且看板发布成功后写入的幂等 stamp
  data/event_ingest_cutover_at.txt  本机制上线水位线：正常任务只消费此后首次发现的事件
  data/.pages/babata-board/   本项目专用的 babata-board 仓库本地克隆（发布用，见下）
```

7 月初始状态（`data/2026-07/` 下三个 JSON）是从一次性人工验证批次迁移过来的：101 个产品组 /
129 个成员 / 129 张产品图，全部已验证。之后每天只在这份状态上做增量。

## 每日流程

`com.spspy.fb-verify` 每天 13:30（Asia/Shanghai）运行。该时刻与 11:30 的主 SP
monitor 错开，并为单页监控的 08:30 日间扫描留出完成窗口。

`run_daily_fb_verify.sh` 依次做：

1. **摄入**：首选读 `~/.spspy-single-page-monitor/single-page-monitor/data/events.jsonl` 中
   `single_page_first_detected` 事件，选出**本机制上线水位线之后、本月**首次发现、但尚未在本项目月度状态中出现的
   单页；月初额外纳入前一天的事件，避免月末晚间扫描跨月遗漏。按现有规则清洗出查询词，
   各自建一个新组并入 `data/<月>/unique_products.json`。
   这是 append-only 事件流：即使夜间有完整单页扫描、次日 `new_hits.csv` 被早晨扫描覆盖，事件
   仍会在下一次 FB 验证时补处理。上线水位线保存于 `data/event_ingest_cutover_at.txt`，避免
   将早于本机制的历史事件误触发为新信号；显式按日期补跑时会越过该水位线。只有事件流缺失时，
   才退回读取部署目录的当月 `new_hits.csv`。
   已有当月健康月度状态时，0 行也正常，流程仍会重建看板；但**新月份首次运行**若没有任何
   产品组，构建器会明确失败且不创建/发布空月看板，也不会推进成功戳。这样历史积压或上游空读
   不会覆盖上一份可用看板后再被误报为成功。
2. **合并**：把归一化查询词相同的组合并——新组撞上已验证过的老组，直接合并进老组（不会
   触发重新查询）；当天多个新命中恰好是同一款产品，也会先合并再只查一次。
3. **验证**：只对本次没有验证记录、且没被标记 `already_verified` 的组，跑 FB 广告库查询
   （单组间隔 8-14 秒，避免打太快；单日最多查 40 组，超出的留到第二天自动续跑；连续 5 组
   空结果视为被限速，直接终止本轮剩余查询，不做长时间重试等待）。
4. **抓图**：对没有缓存过图片的新成员抓产品主图。依次复用上月缓存、尝试 Shopify `.js/.json`、
   `og:image`、已确认广告的同款跨站落地页、广告预览图；最后可用 ffmpeg 截取广告视频首帧。
   HTTP 图片统一升级为 HTTPS，429/403/5xx 做有限退避重试；单产品最多 90 秒，失败项下轮仍会
   重试。上月本地缓存按 1000 条批量落盘且不等待，整步由独立进程组的 20 分钟看门狗约束。
5. **重建看板**：`build_fb_verify_page.py` 重新生成 `data/<月>/fb_verify_dashboard.html`
   （月累计视图，不是当天增量视图）。页面内随 HTML 原子保存该月 active group / checkpoint
   与不可变证据摘要；同月重跑若少了历史状态，只在 `group_aliases`、quarantine、checkpoint alias
   和 checkpoint archive 能共同证明证据无损收敛到当前 active group 时才允许，否则在写入前失败。
   同一 canonical group 的历史成员集合只能增加；已有 positive 的相关广告身份与相关数水位不能
   丢失或降级，terminal negative/zero 不能退回 inconclusive 或在无 alias 审计时互换，但允许升级
   positive；inconclusive 的诊断字段可以继续更新并升级为有结论状态，因此不会冻结正常重试。
   空输入不会覆盖健康页。旧版无基线的页面必须完整匹配旧生成器的唯一脚本结构，并且现有 group
   覆盖其嵌入记录，才会升级为带基线版本；无法识别的 HTML、注释伪装或多个 `RECORDS` 均拒绝。
   构建 CLI 强制显式声明 `--view-kind monthly|batch`：monthly 只能写当月目录的 canonical 文件，
   batch 只能写同月 `batches/` 下的非 canonical 文件，批次筛选不能改写完整月度页。
6. **发布**：`publish_fb_pages.py` 在本项目专用的 babata-board 克隆
   （`data/.pages/babata-board/`）中，只允许根目录月度页和本月
   `fb_verify_batches/<月份>/<批次>.html`。发布锁直接绑定持久 `.pages` 目录 inode，覆盖远端同步、
   原子落盘、暂存、commit、push 和远端核验的完整事务；开始时要求 worktree/index clean 且
   HEAD 精确绑定 `origin/main`。提交前后分别核对允许路径、index/tree/diff 及 blob 原始字节，
   再以不可变 commit SHA 和 exact `--force-with-lease` 推 main；推送后重新读取远端 ref/blob。
   在任何 checkout 写入前，发布器会在 `.pages` 父目录写入并 `fsync` 一份私有 crash journal：
   固化仓库 identity、初始远端 SHA、允许路径和每个来源页面 SHA-256；暂存 tree、commit 与
   tree 校验完成后也会持久补记。若进程在写入、`git add`、commit、push 或清理之间被 `SIGKILL`，
   下一次拿到同一目录锁后只会恢复这份 journal 能严格证明的状态：远端仍在初始 SHA 时回滚目标，
   远端已到已验证 commit 时核验远端 blob 后收敛本地。journal 损坏、origin/路径/字节不符、未知
   dirty/untracked 状态，或远端处于第三个 SHA 时均 fail-closed，绝不覆盖用户字节。正常安全回滚
   或成功收敛后才删除 journal（删除及父目录同样 `fsync`），避免坏本地 commit 污染下次重试。
   看板地址：**https://tonyaiuser.github.io/babata-board/fb_verify_dashboard.html**
7. **钉钉推送**：仅当第 5/6 步（重建看板 + 发布）都成功、且今天确实有新组被验证过
   （`verified > 0`）时，发一条独立的钉钉 markdown 消息（标题"FB 投放验证已更新"，正文含
   本轮新增验证组数 / 🔥新起投(≤3天)数 / 多站跨投(≥3站)数，以及确认产品的标题和首次/最近
   起投日期摘要；广告条数明确标为“首屏相关样本”，不冒充 FB 总量；最多展示 10 个名称。每次推送同时生成不可变的本轮图文看板
   `fb_verify_batches/<月份>/<时间>.html`，卡片沿用月度看板样式，展示产品主图、来源单页、广告样本
   和投放日期；钉钉分别提供本轮看板与完整月度看板入口）。0 新增不发；同一个
   产品组写入 checkpoint 后不会再次算作“本轮新增”，所以早晚两轮不同新组可以各自推送而不重复；
   发送失败按 best-effort 处理，只记错误日志，不影响本次运行的整体成功状态。

## 夜间完整扫描 + FB 验证

`com.spspy.single-page-fb-nightly` 每天 21:05（Asia/Shanghai）运行
`run_nightly_single_page_fb_verify.sh`：

1. 调用部署中的单页监控 `run_daily.sh` 做一次完整扫描、重建并发布单页看板，但传
   `SP_SINGLE_PAGE_SEND_DINGTALK=0`，不发送未经 FB 验证的原始单页消息。
2. 以 `FB_VERIFY_ALLOW_SAME_DAY=1` 调用 FB 流程。它会绕过“当天已成功”的日间幂等戳，
   但仍只查询新进入 checkpoint 的产品组；没有新单页时不会请求 Facebook，也不会发钉钉。
3. 若夜间新增组在 Facebook 广告库验证到相关活跃投放，则重建/发布同一个月累计 FB 看板，并
   发送一条独立钉钉消息。

选 21:05 是为了错开每个整点运行的 `ai.openclaw.sp.hourly-check`，避免两条任务同一时刻访问
Top 站点而叠加限速。FB 查询出错的组不会写成“已验证”，会留到下一轮自动重试。

这与每小时 `ai.openclaw.sp.hourly-check` 不同：后者仍是轻量产品可用性巡检，**不做**单页
分类，也不会触发 FB 验证。

macOS 的 launchd 进程可能不允许 Node 读取 Desktop 下的脚本和 JSON 数据，因此线上任务从
`~/.spspy-fb-verify/fb-verify/` 运行隐藏部署。`sync_deploy.sh` 只部署代码：先完整复制到独立
`releases/.<id>.stage`，通过 Python/Node/Bash 与 launchd plist 校验后再原子切换 `current`。launchd 始终调用根目录
稳定入口，入口只解析一次 `current`，因此部署切换不会混用新旧脚本。切换前会先安装部署 gate，
阻止新的稳定入口启动，并等待 gate 前已经启动的旧 release 进程退出；失败时先回滚 current 和全部
稳定文件，只有完整回滚持久化成功才撤 gate。若任一 restore/fsync 失败，三个稳定可执行入口会
统一收敛到已验证 release 的 gate-aware launcher，同时保留 gate 与 rollback 证据。实时状态唯一保存在根目录
`data/`；该目录必须由独立的显式初始化流程预先创建。部署不会创建它，看到空 data 时也绝不会从
源码复制或初始化任何状态文件。
修改源码后必须再次运行 `./sync_deploy.sh`。查看线上状态和看板产物时，以隐藏部署目录为准。

发布仍使用同一个 babata-board 仓库和 `gh auth git-credential` 凭证，但**用的是自己独立的一份
本地克隆**（不共用单页监控的 `.pages/babata-board-pages-main`）和 FB 专用的发布事务；允许路径
严格限定为 FB 月度页及其当月批次页，不会碰仓库里的 `single-page-monitor/`、
`sp_picker_dashboard.html` 等其它内容。

钉钉推送同理：**代码完全独立**（`scripts/notify_dingtalk.py`，不 import、不修改单页监控的
`run.py`），只是只读复用同一份凭证获取方式——用 `ast` 静态解析
`~/.openclaw/workspace/skills/sp-monitor/run.py` 里的 `DINGTALK_WEBHOOK` / `DINGTALK_SECRET`
两个常量，再用同一套 HMAC-SHA256 签名逻辑直接调 webhook。webhook/secret 不会被硬编码、不会被
打印到 stdout/stderr/日志里。

## 月滚动

`MONTH="$(TZ=Asia/Shanghai date +%Y-%m)"`，每次运行都按当前月份算 `data/<月>/` 路径。新月份
第一次跑会迁移上月所有未解决组及其 retry ledger；已完成组仍只读用于跨月去重与结果/图片复用；
不会修改上月文件。
月初额外接住前一天事件时，已经在上月处理过的成员不会再次建组或触发通知。
`ingest_new_hits.py` 会把严格日历格式的 target month 持久写入 `unique_products.json`；旧状态缺失
该字段时随本次原子更新补齐。unique/checkpoint 顶层、group、checkpoint/archive/retry 记录都带
`state_month`；已有字段、上月 unique/verify 文件路径与嵌套状态、或任一构建输入目录与目标月份
不一致时拒绝覆盖，避免相同 GID 在不同月份间误复用。

## 幂等 & 并发保护

- `data/.pages/` 目录 inode：FB Git 发布器直接对这个持久目录持有非阻塞内核锁，锁覆盖 pull/fetch、
  写文件、commit、immutable-SHA lease push 和远端核验；普通 `.publish.lock` 文件即使被
  rename/recreate 也不能制造第二把锁。竞争发布直接 exit 75。
- `data/run_daily.lock`：daily/nightly 共用的兼容锁入口；它原子指向 owner 目录。公开 `pid`
  固定写 `0`，这是 POSIX process-group compatibility sentinel：旧版常见的
  `kill -0 "$old_pid"` 会把它恒定判为存活，从而不会在正常 owner 换代后误删下一代锁；真实 owner
  身份不依赖这个 pid，而由 owner token、owner 目录名、继承 FD 和原始外层 PID 共同验证。外层
  脚本在所有状态落盘、日志及回滚处理完成后，会用 `exec` 替换自己为释放 helper；因此 helper 的
  **自身 PID** 必须仍等于最初 owner PID。嵌套进程即使继承了 FD/环境，或自行 `exec` helper，也
  无法提前释放父任务的锁。目录内
  `.fcntl` 才是真正的内核锁。竞争调用直接 exit 75，旧版 mkdir 锁客户端也只会
  看到 sentinel 后退出，不会删除新锁。正常 owner 会在仍持有 FD 的最终 cleanup 中安全删除自己
  发布的 symlink/owner；kill -9 时内核锁虽会释放，但公开 owner 证据会保留并阻止自动复用，避免
  cached legacy reader 与下一代并发。夜间任务调用 daily 时会校验并复用继承的同一个锁描述符。
- `data/last_attempt_date.txt`：每次取得运行锁后记录一次尝试，便于审计；它不会阻止同日重试。
- `data/last_attempt_id.txt` 与 `data/pipeline_status.json`：开始时先写唯一 run id 和
  `in_progress`；收尾时在锁内写最终状态。只有 stamp、attempt id、最终 succeeded 状态三者属于
  同一次 run，普通同日调用才会幂等跳过。
- `data/last_published_success.txt`：只有发布启用且成功、且本轮没有 `terminated_early`、截断或
  待重试/失败组，并且汇总与最终状态均已成功落盘后，才在最终 cleanup 写入今天日期。强制同日
  增量开始时会先让旧 stamp 失效；本轮部分失败不会让后续普通调用误跳过。
- 任何一步失败（`set -euo pipefail`），流水线会中止且**不写** stamp，锁会被释放，明天/手动
  重跑都会重新尝试。失败详情看 `.err.log`。

## 手动命令

```bash
# 源码修改后先同步到线上隐藏目录
/Users/tonyaiuser/Desktop/spspy/fb-verify/sync_deploy.sh

# 正常手动跑一次（等价于 launchd 会做的事）
/Users/tonyaiuser/.spspy-fb-verify/fb-verify/run_daily_fb_verify.sh

# 只想验证逻辑、不想真的发布到 GitHub Pages
FB_VERIFY_PUBLISH=0 /Users/tonyaiuser/.spspy-fb-verify/fb-verify/run_daily_fb_verify.sh

# 手动测试/验收时，不想真的发钉钉打扰用户：两种方式二选一
/Users/tonyaiuser/.spspy-fb-verify/fb-verify/run_daily_fb_verify.sh --no-dingtalk          # 完全跳过这一步
/Users/tonyaiuser/.spspy-fb-verify/fb-verify/run_daily_fb_verify.sh --dingtalk-dry-run     # 照常构造消息体并打印，但不读凭证、不真发

# 仅补跑某一天的持久单页事件（正常情况下不需要；常规运行会自动补所有未处理项）
FB_VERIFY_TARGET_DATE=2026-07-09 /Users/tonyaiuser/.spspy-fb-verify/fb-verify/run_daily_fb_verify.sh

# 想强制同日增量重跑（会先原子失效旧 success tuple）
FB_VERIFY_ALLOW_SAME_DAY=1 /Users/tonyaiuser/.spspy-fb-verify/fb-verify/run_daily_fb_verify.sh

# 查看 launchd 任务状态
launchctl list | grep fb-verify

# 手动触发一次 launchd 任务（不用等到 13:30）
launchctl kickstart -k gui/$(id -u)/com.spspy.fb-verify
```

可调的环境变量（默认值见 `run_daily_fb_verify.sh` 顶部）：

| 变量 | 作用 | 默认值 |
|---|---|---|
| `FB_VERIFY_MONITOR_EVENTS_JSONL` | 首选持久事件流路径 | 单页监控部署目录 `data/events.jsonl` |
| `FB_VERIFY_NEW_HITS_CSV` | 事件流不存在时的 CSV 兜底路径 | 单页监控部署目录当月 `new_hits.csv` |
| `FB_VERIFY_EVENT_CUTOFF_FILE` | 上线水位线文件（常规任务忽略此前事件） | 当前运行目录 `data/event_ingest_cutover_at.txt` |
| `FB_VERIFY_ALLOW_SAME_DAY` | `1`=允许当天第二次增量 FB 流程（夜间编排专用） | 0 |
| `FB_VERIFY_NODE_SCRIPTS_DIR` | Node FB 脚本目录（通常无需设置） | 当前运行目录的 `scripts/` |
| `FB_VERIFY_MAX_GROUPS` | 单日最多查询组数 | 40 |
| `FB_VERIFY_BLANK_STREAK` | 连续空结果熔断阈值 | 5 |
| `FB_VERIFY_TARGET_DATE` | 仅摄入该日期的持久首次发现事件（补跑用） | 空=本月全部未处理事件（月初额外接住前一日） |
| `FB_VERIFY_PUBLISH` | 是否发布到 GitHub Pages | 1 |
| `FB_VERIFY_PAGES_REPO` / `FB_VERIFY_PAGES_DIR` | 发布用的仓库地址/本地克隆路径 | babata-board / `data/.pages/babata-board` |
| `FB_VERIFY_LOG_DIR` | 日志目录 | `~/.openclaw/logs/automation` |
| `FB_VERIFY_IMAGE_WALL_TIMEOUT_SECONDS` | 抓图整步 wall-clock 上限；必须是有限数，生产范围 60–1200 秒 | 1200 |
| `FB_VERIFY_IMAGE_WATCHDOG_GRACE_SECONDS` | 抓图进程组 TERM 后升级 KILL 的宽限；必须是有限数，生产范围 1–30 秒 | 10 |
| `FB_VERIFY_DINGTALK` | 是否启用钉钉推送（`0`=等同 `--no-dingtalk`） | 1 |
| `FB_VERIFY_DINGTALK_DRY_RUN` | `1`=等同 `--dingtalk-dry-run`（只打印不真发） | 0 |
| `FB_VERIFY_DINGTALK_CONFIG` | 读取 webhook/secret 的配置文件路径 | 单页监控同一份 `sp-monitor/run.py` |

命令行参数（追加在脚本后面，launchd 正常调度不会传）：`--no-dingtalk` / `--dingtalk-dry-run`。

## 日志 & 故障排查

- `~/.openclaw/logs/automation/fb_verify.log`：每步带时间戳的完整流程日志，结尾有一行
  `SUMMARY new_groups_added=... fb_verified_today=x/y ... publish=... dingtalk=...` 汇总
  （`dingtalk=` 取值：`sent` 真发成功 / `dryrun-ok` 演练模式 / `skipped(0-new-groups)` 本轮
  没有新增验证组不发 / `skipped(0-new-matched-groups)` 完成查询但没有确认相关投放 / `off`
  命令行禁用 / `failed`
  发送失败但不影响整体成功）。
- `~/.openclaw/logs/automation/fb_verify.err.log`：stderr（Playwright 报错、git 报错等）。
- `~/.openclaw/logs/automation/fb_verify.launchd.{out,err}.log`：launchd 的 `StandardOutPath` /
  `StandardErrorPath`，是原始兜底日志（能抓到脚本自己的 tee 还没接管之前就崩溃的情况，比如
  bash 语法错误、`node`/`python3` 找不到）。跟上面两个 `.log` 不是一份——正常运行时内容基本
  重复，只在"脚本还没跑到 `log()`/`tee` 就挂了"这种极端情况下才有独立价值，故意不指向同一个
  文件，避免同一份日志里每行重复两次。
- 常见问题：
  - **"another run is active"（exit 75）**：通常说明另一个 daily/nightly 进程仍持有内核锁；
    若 owner 因 kill -9 遗留，程序也会保留证据并 fail closed。不要直接删除
    `data/run_daily.lock`。确认没有旧版/cached reader 后，将遗留 owner 与入口一起移走再重跑。
  - **FB 查询连续熔断（terminated_early=true）**：当天大概率被 Facebook 限速，剩余组会在
    第二天自动继续查，不需要人工干预；如果连续多天都熔断，考虑把 `FB_VERIFY_MAX_GROUPS`
    调小或把查询间隔拉长。
  - **FB 页面 HTTP 403 且 0 素材**：结果是不确定，不会再写成“已验证但无投放”；该组保留待重试。
    403 页面若仍成功抓到广告素材，可保留正向证据，并在页面中按首屏样本口径展示。
  - **发布报 `git pull` 冲突 / 认证失败**：先确认 `gh auth status` 是否仍登录着
    `tonyaiuser`；`data/.pages/babata-board/` 是独立克隆，出问题可以直接删了让脚本重新
    clone，不影响单页监控自己的那份克隆。
  - **看板某产品图片失效**：产品图是 Shopify CDN / 站点 og:image 热链，可能过期，属于展示
    问题不是数据问题；广告素材缩略图同理（FB CDN 热链）。

## 红线（部署时的约束，供后续维护参考）

- 不改单页监控（`~/.spspy-single-page-monitor/`）下任何文件，只读它的
  `data/events.jsonl`（事件流缺失时才读 `reports/<月份>/new_hits.csv`）。
- 正常运行遵守 `data/event_ingest_cutover_at.txt` 水位线，防止历史事件被误认为新信号；
  有意补历史时用 `FB_VERIFY_TARGET_DATE`。
- 只有当新组完成 FB 验证、确认存在相关活跃投放且看板发布成功时才发独立钉钉；原始单页发现本身不冒充“双重验证”结果。
- babata-board 仓库只会增/改主看板 `fb_verify_dashboard.html`，以及同月受限路径
  `fb_verify_batches/<YYYY-MM>/<safe-name>.html` 的批次看板；两者都必须通过发布事务的
  月份、字节和 Git commit 校验。
- `~/Desktop/spspy/fb-verify/` 是开发源码，`~/.spspy-fb-verify/fb-verify/` 是线上运行副本与
  实时状态；同步代码不能创建、覆盖或改变后者的 `data/`。
