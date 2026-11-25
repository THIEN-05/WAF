# Benchmark

## Gate G microbenchmarks — 2026-11-24

Measured in WSL Ubuntu/Linux amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz, GOMAXPROCS=12, `-benchtime=1000x -benchmem`:

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkAccessCheck` | 200.7 | 17 | 1 |
| `BenchmarkRateLimitAllow` | 901.2 | 298 | 7 |
| `BenchmarkWAF` | 6,986 | 6,191 | 26 |

Commands: `go test -run '^$' -bench '^BenchmarkAccessCheck$' -benchtime=1000x -benchmem ./edge/internal/access`; analogous command with `BenchmarkRateLimitAllow` in `./edge/internal/ratelimit` and `BenchmarkWAF` in `./edge/internal/waf`. The WAF benchmark fixture includes the required `owasp-sqli` tag. Historical benchmark entries below measured on Windows are retained for traceability and are **Windows, not performance evidence**; use Linux/WSL measurements for current comparisons.

## P4e — toàn phạm vi package, cửa sổ regex và deadline body — 2026-11-24

Đo trên WSL Ubuntu/Linux amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz; `-benchtime=100x -benchmem`. Mỗi body benchmark đặt đúng gói/cap 8/64/256 KiB; WAF budget 2 ms. `budget-exceeded-%` là tỷ lệ request mà WAF phát hiện vượt ngân sách và phát `waf_budget_exceeded`; Free áp dụng fail-open, Pro/Enterprise áp dụng fail-closed. Đây là trạng thái/hành vi khi p99 vượt 2 ms, không tuyên bố giới hạn wall-clock cứng.

| Input | Kích thước | ns/op | p50 ns | p99 ns | B/op | allocs/op | vượt budget |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Aho keywords lặp | 8 KiB | 2,031,240 | 2,022,401 | 2,119,558 | 86,889 | 89 | 100% |
| JSON lồng sâu | 8 KiB | 526,361 | 502,373 | 721,825 | 52,720 | 58 | 0% |
| Multipart nhiều phần | 8 KiB | 2,026,020 | 2,020,799 | 2,077,908 | 105,586 | 111 | 100% |
| Aho keywords lặp | 64 KiB | 2,051,275 | 2,025,607 | 2,193,289 | 340,253 | 138 | 100% |
| JSON lồng sâu | 64 KiB | 2,040,638 | 2,030,383 | 2,173,155 | 290,733 | 96 | 100% |
| Multipart nhiều phần | 64 KiB | 2,024,580 | 2,013,386 | 2,087,377 | 382,097 | 167 | 100% |
| Aho keywords lặp | 256 KiB | 2,027,176 | 2,016,330 | 2,094,294 | 1,037,041 | 142 | 100% |
| JSON lồng sâu | 256 KiB | 2,041,659 | 2,026,347 | 2,163,780 | 987,102 | 99 | 100% |
| Multipart nhiều phần | 256 KiB | 2,035,146 | 2,018,850 | 2,122,944 | 1,057,522 | 157 | 100% |
| 200 tham số query | — | 2,056,106 | 2,025,775 | 2,379,751 | 213,693 | 2,157 | 100% |

Lệnh đo: `go test -run '^$' -bench '^BenchmarkWAFWorstCase$' -benchtime=100x -benchmem ./edge/internal/waf`.

Đo tải nhẹ song song P4e: `TestWAFParallel50ReportsP99AndBudgetAction` chạy 50 goroutine × 5 request JSON 8 KiB, p50 **2,090,501 ns**, p99 **22,048,227 ns**, và **250/250** chạm ngân sách 2 ms do đồng hồ tường bao gồm scheduler wait. Đây là baseline cũ; benchmark P4f thay chính sách budget.

FPR body lớn: test 30 mẫu sạch cho mỗi paranoia (JSON, form, text, multipart) ghi **0/30 (0.00%)** ở P1, P2, P3 và P4. Ngưỡng test cố định 0%; nếu body vượt cap, đó là trường hợp thiếu quan sát được báo riêng bằng `waf_body_truncated`, không tính là mẫu sạch đầy đủ.

Thay đổi thuật toán: Aho-Corasick quét phạm vi theo gói theo block 4 KiB với overlap 512 byte; regex RE2 chạy trên cửa sổ tối đa 512 byte quanh keyword. **Chỉ candidate windows trong byte đã buffer** có thể giữ đầu/cuối; khi body vượt entitlement, edge chỉ buffer prefix và không đọc tail, gắn `waf_body_truncated`, cộng mặc định 3 điểm, rồi áp fail mode. Free fail-open có padding bypass risk ở body tail; xem mitigations trong DECISIONS.

## P4f — deterministic WAF budget and overload

> The P4f load results below predate P4f-fix and are historical. See the addendum below for the current fuse policy and CI perf job.

Plan work caps: Free 128 KiB / 256 normalize block steps / 128 regex windows; Pro 256 KiB / 512 / 192; Business 384 KiB / 768 / 256; Enterprise 512 KiB / 1,024 / 384. The current `budget_ms` is a coarse wall fuse (default/minimum 250 ms, configurable up to 5,000); while active WAF work exceeds GOMAXPROCS, the threshold scales with estimated runnable backlog and WAF EWMA and is capped at 10 s. A fuse trip marks a partial scan and adds one point, but does not apply fail-mode below the anomaly threshold. Work-cap events still use deterministic package caps and the configured fail-mode.

Measured on WSL Ubuntu/Linux amd64, Go 1.26.11, Intel i5-11400H (6 cores/12 logical CPUs), GOMAXPROCS=12; command `go test ./edge/internal/waf -run '^$' -bench '^BenchmarkWAFLoadMatrix$' -benchtime=200x -benchmem`. Each cell runs 200 requests; p50/p99 and work/fuse rates are per-request samples; allocs/op is Go benchmark allocation per request. The table shows min–max over the 12 combinations of body 8/64/256 KiB and repeated-Aho, deep-JSON, multipart, and 200-query-parameter shapes:

| Goroutines | p50 ns | p99 ns | allocs/op | work-cap % | fuse % |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 460,845–38,778,809 | 1,008,564–45,479,975 | 59–2,454 | 0–100 | 0 |
| 10 | 1,726,275–84,023,832 | 3,202,801–101,019,255 | 62–2,462 | 0–100 | 0–4.5 |
| 50 | 2,550,293–307,082,113 | 27,030,867–1,176,596,897 | 63–2,443 | 0–100 | 0–7.0 |
| 200 | 17,999,359–1,043,977,640 | 33,467,356–1,602,541,791 | 64–2,424 | 0–98.5 | 0–9.0 |

These are broad scenario ranges, not a service-level guarantee. High-concurrency worst-case requests still have p99 above one second and a nonzero fuse rate; work-cap rates reach 100% for some cases. That confirms bounded fail-mode behavior remains a risk for paid fail-closed sites with large valid requests. The regression test separately covers 50 concurrent 8 KiB traffic: default fuse **0/250**, clean rejects **0/20**, prefix SQLi blocked **50/50**; p50 **6,061,300 ns**, p99 **63,354,000 ns**, GOMAXPROCS=12/12 CPUs. GOMAXPROCS 2/4/12 clean 50-goroutine test: fuse **0/250** and rejected clean requests **0/250** in each setting.

Work-cap cases are marked incomplete and follow the configured fail mode; benchmark mode is monitor, so work-cap percentage does not itself mean those requests were blocked. Free defaults fail-open; closed paid plans may reject incomplete scans. The older measurements show scheduler delay can exceed a short wall fuse, so those results do not validate the current policy.

### P4f-fix — required perf job (superseded p99 gate)

`TestWAFParallel50GOMAXPROCSMatrix` and `TestWAFCleanFailClosedAtOnePWithCPUBackground` are tagged `perf`; CI runs both in a required, non-race job with `-count=30`. The matrix covers GOMAXPROCS 1/2/4/N and 50/200 goroutines; the background case uses GOMAXPROCS=1, 200 goroutines and a CPU-burning worker. Correctness remains asserted on every repetition: zero clean fail-closed rejects, 100% in-scope attack blocks, and zero fuse trips. The old 69 ms wall-clock gate described below is retired because it was scheduler-sensitive. Deterministic fuse/work-cap policy tests remain in the normal race suite.

## WSL/Linux results supplied by the user

The user supplied this `taskset` run summary (30 repetitions; Linux, 2 CPUs pinned for the GOMAXPROCS matrix). Per cell: 0 clean rejects, 100% of in-scope attacks blocked, fuse 0. The provided summary contains aggregate p50/p99, not exact p99 per cell; the table therefore marks per-cell p99 as not separately reported.

| OS | CPUs pinned | GOMAXPROCS | Goroutines | Runs | p50/request | p99/request per cell | Clean rejects | Attack blocked | Fuse |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| WSL/Linux | 2 | 1 | 50 | 30 | ~135 µs | included in aggregate 0.16–23 ms | 0 | 100% | 0 |
| WSL/Linux | 2 | 1 | 200 | 30 | ~135 µs | included in aggregate 0.16–23 ms | 0 | 100% | 0 |
| WSL/Linux | 2 | 2 | 50 | 30 | ~135 µs | included in aggregate 0.16–23 ms | 0 | 100% | 0 |
| WSL/Linux | 2 | 2 | 200 | 30 | ~135 µs | included in aggregate 0.16–23 ms | 0 | 100% | 0 |
| WSL/Linux | 2 | 4 | 50 | 30 | ~135 µs | included in aggregate 0.16–23 ms | 0 | 100% | 0 |
| WSL/Linux | 2 | 4 | 200 | 30 | ~135 µs | included in aggregate 0.16–23 ms | 0 | 100% | 0 |

The historic p99 ceiling of **69 ms = 3 × 23 ms** has been removed. GitHub runner logs later showed a GOMAXPROCS=4/200-goroutine p99 varying from about 38–48 ms on passes to 69.88–73.07 ms on three failures, while clean rejects stayed 0/800, attacks were blocked 200/200 and fuse stayed 0/1000. These are request-start wall times from a shared 4-CPU runner and are diagnostics, not a required threshold.

Request wall latency starts immediately before `Phase.Handle` after the test goroutine is scheduled and the request/context are built. It includes WAF phase execution and any preemption during it, but excludes time waiting for the goroutine to become runnable. It is not end-to-end listener latency.

### P4f-fix stabilization — CPU work timing and repeated summaries

- The required deterministic CI gate is evaluated on every execution of every matrix cell: clean rejects must be 0, in-scope attacks must be 100% blocked, and fuse trips must be 0. These assertions are not retried or averaged away.
- Linux measures each `Phase.Handle` interval using the locked OS thread's `getrusage(RUSAGE_THREAD)` CPU time. The metric excludes time when the thread is descheduled; wall time is retained only for reporting. A serial scan baseline is measured on the same runner and GOMAXPROCS for each repetition. The high-percentile scan CPU gate is **10 × the median serial p99**, evaluated against the median loaded p99 across the 30 repetitions.
- The only wall p99 failure gate applies when goroutine count is no greater than `runtime.NumCPU()`: median p99 over the 30 repetitions must be no more than 5 × the same-runner serial p99. This matrix currently uses 50 and 200 workers, so its wall p99 values do not fail CI. For overloaded cells, wall p99 is recorded and compared with historical baselines as a warning only; the supplied same-runner 4-CPU baselines are 30 ms for GOMAXPROCS=2/200 and 48 ms for GOMAXPROCS=4/200, with warning at >2×. No retry is used; latency aggregation uses the median of 30 runs, and correctness is checked each run.
- Each run logs runner name, Linux OS, `nproc`, Go CPU count, GOMAXPROCS, goroutines, p50/p99 wall latency, p50/p99 thread CPU time, serial baseline, and correctness counters. `TestMain` writes all repetitions to JSON and a median-per-cell table to `$GITHUB_STEP_SUMMARY`; CI uploads JSON as `waf-perf-results` even when the job fails.
- Baseline source: user-supplied GitHub runner measurements (Linux, 4 CPUs) in the P4f-fix request. CPU-time thresholds are recalibrated from serial scans on the same runner per run; the wall p99 warning baselines use the observed passing maxima above. The warning never fails CI.

WSL/Linux final local run used the exact CI test command with `-count=30` (12 CPUs; `nproc=12`, not the GitHub 4-CPU runner). It passed in 25.824 s. Every matrix cell and the background case had zero clean rejects, 100% attacks blocked, and zero fuse trips. Table values are medians of each run's p50/p99 over 30 repetitions; totals aggregate all requests across repetitions. This WSL `RUSAGE_THREAD` implementation has microsecond resolution, so many CPU p50 values display as zero.

| Cell | OS | CPUs/nproc | GOMAXPROCS | Goroutines | Runs | request p50 | request p99 | scan CPU p50 | scan CPU p99 | Clean rejects | Attacks blocked | Fuse |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| matrix | Linux/WSL | 12/12 | 1 | 50 | 30 | 138.203 µs | 226.103 µs | 0 | 4.003 ms | 0/6,000 | 1,500/1,500 | 0/7,500 |
| matrix | Linux/WSL | 12/12 | 1 | 200 | 30 | 139.508 µs | 226.049 µs | 0 | 4.003 ms | 0/24,000 | 6,000/6,000 | 0/30,000 |
| matrix | Linux/WSL | 12/12 | 2 | 50 | 30 | 123.984 µs | 8.680 ms | 0 | 3.182 ms | 0/6,000 | 1,500/1,500 | 0/7,500 |
| matrix | Linux/WSL | 12/12 | 2 | 200 | 30 | 120.705 µs | 18.141 ms | 0 | 3.587 ms | 0/24,000 | 6,000/6,000 | 0/30,000 |
| matrix | Linux/WSL | 12/12 | 4 | 50 | 30 | 131.473 µs | 7.704 ms | 0 | 2.126 ms | 0/6,000 | 1,500/1,500 | 0/7,500 |
| matrix | Linux/WSL | 12/12 | 4 | 200 | 30 | 125.203 µs | 22.224 ms | 0 | 2.515 ms | 0/24,000 | 6,000/6,000 | 0/30,000 |
| matrix | Linux/WSL | 12/12 | 12 | 50 | 30 | 252.494 µs | 10.653 ms | 118 µs | 1.047 ms | 0/6,000 | 1,500/1,500 | 0/7,500 |
| matrix | Linux/WSL | 12/12 | 12 | 200 | 30 | 223.597 µs | 32.104 ms | 0 | 1.145 ms | 0/24,000 | 6,000/6,000 | 0/30,000 |
| CPU background | Linux/WSL | 12/12 | 1 | 200 + 1 burner | 30 | 141.105 µs | 229.508 µs | 0 | 4.003 ms | 0/24,000 | 6,000/6,000 | 0/30,000 |

The CI job writes the same per-cell table to the workflow summary and uploads JSON containing all 30 raw repetitions. Local WSL values are diagnostic only and are not used as the GitHub runner baseline.

For the one-core CPU-background test, the user's Linux summary reports 30 runs and `clean_rejected=0/800`; p99/attack/fuse counts for that specific Linux run were not supplied. The required perf test independently checks 200 goroutines + one CPU burner and reports all counters.

The Windows measurements below were collected by the earlier worker-mean instrumentation. They remain historical diagnostics and are not the WSL/Linux baseline used for the 69 ms gate.

Windows 11 sandbox run, `GOMAXPROCS=2 go test -tags=perf -count=30 -v ./edge/internal/waf -run '^TestWAFParallel50GOMAXPROCSMatrix$'`, host reports 12 CPUs and the test itself covers GOMAXPROCS 1/2/4/12 × 50/200 goroutines. All 30 runs passed: zero clean rejects, zero fuse trips, all 50/50 or 200/200 attack requests blocked. The 30-run p50/p99 ranges of per-worker mean request latency (ns) from the older instrumentation were:

| GOMAXPROCS | Goroutines | p50 range ns | p99 range ns |
| ---: | ---: | ---: | ---: |
| 1 | 50 | 0–203,400 | 260,100–1,672,500 |
| 1 | 200 | 0–149,300 | 1,009,540–2,026,340 |
| 2 | 50 | 0–211,840 | 202,820–3,915,760 |
| 2 | 200 | 0–3,908,660 | 5,956,900–20,360,160 |
| 4 | 50 | 0–1,801,860 | 1,191,260–3,109,880 |
| 4 | 200 | 211,360–4,802,280 | 4,205,100–8,804,800 |
| 12 | 50 | 400,720–2,582,580 | 400,720–3,182,960 |
| 12 | 200 | 2,700,700–5,639,580 | 6,253,200–9,303,320 |

This Windows timer reported 0 for some worker mean p50 values; those p50 cells are below its measured resolution and are not a usable latency baseline. CPU affinity was not pinned; this is not the requested Linux `taskset` run.

Current request-start instrumentation, Windows sandbox (`OS=windows`, 12 reported CPUs), same two tests with `-count=30`: each matrix cell passed all 30 runs, 0 clean rejects, 100% attacks blocked, 0 fuse. The p99 ranges (ns) per cell were:

| OS | CPUs | GOMAXPROCS | Goroutines | Runs | p50 range ns | p99 range ns |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Windows | 12 | 1 | 50 | 30 | 0 | 1,099,400–7,715,800 |
| Windows | 12 | 1 | 200 | 30 | 0 | 1,719,700–7,182,100 |
| Windows | 12 | 2 | 50 | 30 | 0 | 1,280,200–16,079,500 |
| Windows | 12 | 2 | 200 | 30 | 0 | 8,146,200–62,784,100 |
| Windows | 12 | 4 | 50 | 30 | 0 | 1,822,700–9,585,100 |
| Windows | 12 | 4 | 200 | 30 | 0 | 4,113,400–31,010,200 |
| Windows | 12 | 12 | 50 | 30 | 0–557,900 | 2,031,000–10,134,900 |
| Windows | 12 | 12 | 200 | 30 | 0–521,600 | 10,505,900–27,830,800 |

The CPU-background case (GOMAXPROCS=1, 200 goroutines plus one burner) passed 30/30: clean rejects **0/24,000**, attacks **6,000/6,000**, fuse **0/30,000**, p99 **1,545,300–7,431,100 ns**. Background worker completed 29,622,272–134,742,016 iterations per run. P50 reported 0 in most cells due timer resolution. These are Windows measurements, not physical CPU pinning or a Linux baseline.

Test loopback thật cho body chậm/treo/đứt giữa chừng PASS trong WSL Ubuntu; deadline đọc mặc định 1 giây làm handler kết thúc, paid fail-closed trả 403. `TestPerIPConnectionLimit` tiếp tục nằm trong suite listener và được xác minh cùng race suite. Test loopback chỉ chạy ngoài sandbox Windows.

Các p99 singleton vượt 2 ms nhẹ trong phần lớn workload và body 8 KiB dạng lặp/multipart; phần vượt ngân sách phát tag budget và xử lý theo plan (Free open, paid close). Độ trễ 50 goroutine cao rõ rệt nhưng toàn bộ request vẫn fail-closed. Allocations tăng theo kích thước body, nhưng body buffer có cap theo plan; test heap sau warm-up 3.000 request vẫn giới hạn heap tăng dưới 4 MiB. Kết quả là phép đo một máy, không đảm bảo hiệu năng sản xuất.

Corpus ngoài do người dùng cung cấp được đo bằng `sh scripts/measure-waf-corpus.sh /path/to/corpus-v3`; script chỉ đọc `attacks.tsv` và `clean.tsv` ở thư mục đó, không nạp hay sửa luật. Corpus v2 trong repo vẫn là **dev**, không phải held-out; chưa có kết quả Coraza/CRS.

## P4d — giới hạn scan và coverage dev — 2026-11-23 (lịch sử; trần đã bị P4e supersede)

### Xác minh trên corpus v2 (dev)

Theo chỉ dẫn mới, toàn bộ corpus v2 là **dev** vì đã bị nhìn thấy; các số cũ dưới tiêu đề “held-out v2” không còn được xem là đánh giá held-out. Không tạo corpus v3. `TestWAFCorpusMetrics` in tất cả mẫu v2 bị lọt ở paranoia 1; `TestAttackMutations` in danh sách biến thể lọt, tách theo mẫu gốc đã bắt/chưa bắt. Lệnh tự chạy và đọc đủ miss list:

```sh
go test -count=1 -v ./edge/internal/waf -run '^(TestWAFCorpusMetrics|TestAttackMutations)$'
```

Đo lại sau các luật P2 (40 mẫu mỗi nhóm, 330 mẫu sạch). FPR là 0/330 cho mỗi paranoia. TPR v2 chỉ là số dev:

| Nhóm | P1 | P2 | P3 | P4 |
| --- | ---: | ---: | ---: | ---: |
| SQLi | 55.0% | 70.0% | 70.0% | 70.0% |
| XSS | 90.0% | 100.0% | 100.0% | 100.0% |
| Traversal/LFI | 50.0% | 62.5% | 62.5% | 62.5% |
| RCE | 35.0% | 45.0% | 45.0% | 45.0% |
| Deserialization | 27.5% | 40.0% | 40.0% | 40.0% |
| RFI | 65.0% | 90.0% | 90.0% | 90.0% |
| SSRF | 80.0% | 90.0% | 90.0% | 90.0% |
| XXE | 75.0% | 75.0% | 75.0% | 75.0% |
| SSTI | 70.0% | 70.0% | 70.0% | 70.0% |
| Protocol | 100.0% | 100.0% | 100.0% | 100.0% |
| Scanner UA | 90.0% | 90.0% | 90.0% | 90.0% |
| Sensitive file | 90.0% | 90.0% | 90.0% | 90.0% |

Các nhóm mẫu v2 bị lọt gồm SQLi boolean/HAVING ở form/JSON/cookie; XSS `onpageshow`; traversal percent/double-encoding trong form/JSON; RFI/SSRF trong cookie và một số JSON; RCE newline/command variants; XXE ở JSON; SSTI/deserialization marker ở cookie/JSON; UA `httpx`; path `/config.php.orig`. Lệnh test phía trên in danh sách đầy đủ với giá trị từng mẫu. Việc mẫu nằm trong target mà luật không quét được là một phần nguyên nhân coverage thấp; body hiện là raw prefix chứ chưa parse field của JSON/multipart.

Paranoia khác nhau do các rule P2 được áp dụng ở ngưỡng tương ứng; trên v2 P2 tăng ở bảy nhóm nêu trên và FPR vẫn 0/330. P3/P4 không tăng thêm trên v2: các mẫu đó không kích hoạt các pattern nghiêm ngặt hơn. Đây không phải chứng cứ để khẳng định P3/P4 tốt hơn; cần corpus độc lập.

Mutation v2 (tự sinh, **không phải held-out**): biến thể từ mẫu gốc đã bắt **820/841 (97.5%)**; từ mẫu gốc đã lọt **61/435 (14.0%)**. Test in từng mutation miss, kể cả trạng thái phát hiện mẫu gốc.

### Giới hạn và benchmark thời gian

Scan hiện có trần request 4 KiB, mỗi mục tiêu 2 KiB, body prefix tối đa 1 KiB; query tối đa 8 KiB/64 tham số. Mục tiêu được xử lý theo URI → query → header → cookie → body; deadline được kiểm tra giữa các bước normalize và mỗi bốn rule. Body quá dài gắn `waf_body_truncated` và mặc định cộng 3 điểm (`0` hoặc bỏ trống dùng mặc định; cấu hình 1–5). Body được buffer prefix có giới hạn và phát lại trước phần dư đang stream tới origin. Test khẳng định body lớn có SQLi ngay prefix vẫn bị bắt, và origin đọc lại đủ body 8/64/256 KiB.

Benchmark p50/p99 và `allocs/op` đo trên WSL/Linux, Go 1.26.11, amd64, Intel Core i5-11400H @ 2.70 GHz; `-benchtime=100x`. Body request có kích thước entitlement 8/64/256 KiB, nhưng WAF chỉ quét prefix tối đa 1 KiB. Các số đều dưới 2 ms; hình dạng xấu nhất là 200 query params, p99 1,879,880 ns/op.

| Input | Kích thước | ns/op | p50 ns | p99 ns | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Aho keywords lặp | 8 KiB | 266,038 | 258,347 | 360,649 | 15,990 | 42 |
| JSON lồng sâu | 8 KiB | 55,819 | 54,233 | 73,298 | 12,424 | 41 |
| Multipart nhiều phần | 8 KiB | 620,960 | 613,913 | 711,515 | 18,218 | 46 |
| Aho keywords lặp | 64 KiB | 256,143 | 253,615 | 311,142 | 15,991 | 42 |
| JSON lồng sâu | 64 KiB | 58,415 | 56,976 | 83,824 | 12,423 | 41 |
| Multipart nhiều phần | 64 KiB | 662,940 | 673,902 | 728,953 | 18,217 | 46 |
| Aho keywords lặp | 256 KiB | 251,959 | 243,782 | 322,521 | 15,990 | 42 |
| JSON lồng sâu | 256 KiB | 54,891 | 53,684 | 82,362 | 12,047 | 41 |
| Multipart nhiều phần | 256 KiB | 616,303 | 616,099 | 686,198 | 18,217 | 46 |
| 200 query params | — | 1,238,224 | 1,207,666 | 1,879,880 | 125,948 | 836 |

Lần đo ban đầu với cap body 4 KiB cho thấy multipart 256 KiB p99 2,527,739 ns/op, vượt 2 ms. Sau khi hạ trần request/mục tiêu/body từ 8/4/4 KiB xuống 4/2/1 KiB, lần đo cuối cho p99 tối đa 1,879,880 ns/op (200 tham số). Đây là phép đo 100 lần trên một máy, không phải real-time guarantee; đọc body có thể chờ client như ghi trong mục nợ kỹ thuật.

Lệnh đo:

```sh
go test -run '^$' -bench '^BenchmarkWAFWorstCase$' -benchtime=100x -benchmem ./edge/internal/waf
```

Đọc `Request.Body` đồng bộ cũng có thể chờ client gửi tiếp; số byte giới hạn bộ nhớ nhưng không cưỡng chế deadline socket. TODO-3: gắn deadline/read-timeout cho body ở listener rồi benchmark lại trên Linux.

### Corpus bên ngoài

Để đo corpus v3 do người dùng cung cấp mà không đọc hay nạp luật từ đó, đặt thư mục chỉ gồm hai file TSV rồi chạy:

```sh
WAF_CORPUS_DIR=/path/to/corpus-v3 go test -count=1 -v ./edge/internal/waf -run '^TestWAFCorpusMetrics$'
```

Định dạng mỗi dòng: `group<TAB>target<TAB>value`; cần ít nhất 40 attack samples mỗi nhóm và ít nhất 300 clean samples. `WAF_FPR_MAX` (mặc định 0) và `WAF_TPR_MIN` cấu hình ngưỡng đo. Test chỉ mở `attacks.tsv` và `clean.tsv` trong đường dẫn đã cấp; nó luôn tải managed rules của project từ `edge/rulesets`.

## Lưu trữ số đo P4c ban đầu — v2 nay là dev — 2026-11-23

Đo cũ trên Windows amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz. Corpus dev hiện có 261 mẫu tấn công gốc. Tập v1 đã được dùng để nhận diện thiếu hụt và tinh chỉnh; v2 có 480 mẫu (40 mỗi nhóm, 12 nhóm) trên args/JSON/form/multipart/cookie/path/UA/protocol và 330 mẫu sạch. Theo phân loại mới, **v2 là dev**, đã bị nhìn thấy và không phải held-out. Các số dưới đây là lịch sử trước rule P2 bổ sung; bảng v2 hiện hành ở mục P4d.

> Hạn chế: tôi đã đọc pattern khi xử lý kết quả v1 trước khi soạn v2. Vì vậy v2 không độc lập và không phải held-out; cần corpus v3 do người dùng/reviewer cung cấp để đánh giá độc lập. Corpus vẫn do tác nhân tự viết, không đại diện traffic thật.

TPR đếm mẫu có tag nhóm tương ứng; FPR đếm request sạch bị bất kỳ rule nào gắn tag. Chú giải cũ “held-out” bên dưới đã lỗi thời; bảng này là số dev v2 ban đầu. `WAF_TPR_MIN` đặt ngưỡng đo, `WAF_FPR_MAX` áp dụng riêng ở cả P1–P4 (mặc định 0%):

| Nhóm tấn công | Dev v2 | P1 | P2 | P3 | P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| SQLi | 40 | 65.0% | 65.0% | 65.0% | 65.0% |
| XSS | 40 | 90.0% | 90.0% | 90.0% | 90.0% |
| Path traversal/LFI | 40 | 50.0% | 50.0% | 50.0% | 50.0% |
| RFI | 40 | 65.0% | 65.0% | 65.0% | 65.0% |
| RCE/command injection | 40 | 42.5% | 42.5% | 42.5% | 42.5% |
| SSRF/private address | 40 | 80.0% | 80.0% | 80.0% | 80.0% |
| XXE | 40 | 75.0% | 75.0% | 75.0% | 75.0% |
| SSTI | 40 | 70.0% | 70.0% | 70.0% | 70.0% |
| Deserialization | 40 | 27.5% | 27.5% | 27.5% | 27.5% |
| Protocol anomaly | 40 | 100.0% | 100.0% | 100.0% | 100.0% |
| Scanner UA | 40 | 90.0% | 90.0% | 90.0% | 90.0% |
| Sensitive files | 40 | 90.0% | 90.0% | 90.0% | 90.0% |

Dev corpus gốc đo 261/261 (100%) cho các nhóm quy tắc ở P1–P4; marker virtual patch không có trong v2 và chỉ đạt 0% ở P1–P3 / 100% ở P4 như thiết kế. Đây là số dev, không được dùng để khẳng định khả năng bắt thực tế.

| Clean group (330 tổng) | Số mẫu | FPR P1 | FPR P2 | FPR P3 | FPR P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Search EN/VI | 60 | 0% | 0% | 0% | 0% |
| Form | 40 | 0% | 0% | 0% | 0% |
| JSON API | 40 | 0% | 0% | 0% | 0% |
| Code/text kỹ thuật | 40 | 0% | 0% | 0% | 0% |
| Email | 30 | 0% | 0% | 0% | 0% |
| Multipart | 30 | 0% | 0% | 0% | 0% |
| Path hợp lệ (URI và text Windows/Unix) | 30 | 0% | 0% | 0% | 0% |
| URL dài | 20 | 0% | 0% | 0% | 0% |
| GraphQL | 20 | 0% | 0% | 0% | 0% |
| Base64/JWT | 20 | 0% | 0% | 0% | 0% |

Mutation tự sinh từ dev attacks: **347/347 (100.0%)** bị bắt ở biến thể còn giữ ngữ nghĩa: encode URL một/hai lần, khoảng trắng, Unicode prefix; thêm case/comment và toán tử tương đương cho SQLi; thay case tag/attribute cho XSS. Test in toàn bộ miss list nếu tỷ lệ giảm; lần đo này không có miss.

### Hiệu năng input xấu

`-benchtime=10x -benchmem`, cùng máy/toolchain. Mỗi body benchmark cấu hình chính xác giới hạn entitlement 8/64/256 KB; đo cả chuỗi lặp keyword Aho, JSON lồng sâu và multipart nhiều phần. `200_params` đo query có 200 tham số.

| Input | 8 KB ns/op | 64 KB ns/op | 256 KB ns/op | allocs/op ở 8/64/256 KB |
| --- | ---: | ---: | ---: | ---: |
| Aho keyword lặp | 2,510,930 | 14,185,830 | 29,547,040 | 53 / 63 / 88 |
| JSON lồng sâu | 2,145,570 | 7,938,140 | 13,393,910 | 49 / 58 / 76 |
| Multipart nhiều phần | 2,241,040 | 16,670,420 | 26,182,930 | 58 / 70 / 96 |
| 200 tham số | — | 3,358,360 | — | 1,113 |

Body 8/64/256 KB chạy test biên có reader trễ để chắc chắn đường budget vượt 2 ms trả `RuleID=waf_budget`, tag `waf.budget_exceeded` và hành động đúng theo fail-open/fail-closed. Test thêm 200 tham số, keyword lặp, JSON lồng sâu, multipart nhiều phần với clock có kiểm soát. Kiểm tra 3.000 request sau warm-up không làm heap tăng quá 4 MiB; benchmark báo `allocs/op` thực tế ở trên.

**Giới hạn ngân sách:** benchmark cho thấy đọc/xử lý body 64–256 KB mất nhiều hơn 2 ms (một số 8 KB cũng sát/vượt ngưỡng). Phase phát hiện quá hạn và chọn fail_mode sau bước đọc body; hiện không ngắt được việc đọc body theo deadline. `waf_budget_exceeded` được gắn vào decision/tag, nhưng pipeline chưa có sink audit bất đồng bộ để ghi sự kiện này thành log bền vững. Vì vậy chưa thể tuyên bố ngân sách 2 ms được bảo đảm cứng; đây là debt kỹ thuật.

Hai chuỗi path nhạy cảm (`C:/Windows/System32/...` và `/var/log/...`) trong tập sạch được đưa qua text body, không phải URI path: khi thử như URI, rule traversal bắt chúng (2/30). Đây là vị trí đích có ý nghĩa khác nhau; không tính request cố truy cập file hệ thống là benign. Các path URI hợp lệ còn lại không tạo false positive.

Lệnh benchmark: `go test ./edge/internal/waf -run '^$' -bench 'BenchmarkWAF(ManagedClean|ManagedEarlyExit|WorstCase)$' -benchtime=10x -benchmem`.

Các kết quả đều là corpus tự viết; chưa so với Coraza/OWASP CRS (cần mạng và TODO-1 ở dưới). Không diễn giải TPR/FPR trong bảng như tỷ lệ ngoài thực tế.

## Access check và rate limiter — 2026-11-22

Đo trên Windows amd64, Go 1.26.5, Intel Core i5-11400H @ 2.70 GHz. Mỗi benchmark chạy 5 lần; bảng báo median của `ns/op` và số cấp phát ổn định trong cả 5 lần.

| Benchmark | Median | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkAccessCheck` | 126.3 ns/op | 16 | 1 |
| `BenchmarkRateLimitAllow` | 725.1 ns/op | 296 | 7 |

Lệnh đo:

```sh
go test -run '^$' -bench 'Benchmark(AccessCheck|RateLimitAllow)$' -benchmem ./edge/internal/access ./edge/internal/ratelimit -count=5
```

Access benchmark lặp `Phase.Handle` trên một site/policy và IP cố định. Rate-limit benchmark gọi token bucket trên một key cố định với ngưỡng cao để đo đường cho phép. Đây là microbenchmark của hai hàm, không phải throughput request của edge.

## WAF và custom rules — P4 lượt 1 — 2026-11-22

Đo trên Windows amd64, Go 1.26.5, Intel Core i5-11400H @ 2.70 GHz, một lần chạy `-benchmem`:

| Benchmark | ns/op | B/op | allocs/op | Ghi chú |
| --- | ---: | ---: | ---: | --- |
| `BenchmarkWAF` | 3,724 | 6,501 | 27 | Request query sạch, 1 rule có Aho prefilter |
| `BenchmarkRules` | 6,609 | 0 | 0 | 128 custom rule `log`, báo thêm 19.37M rule-eval/s |

Lệnh đo: `go test -run '^$' -bench 'Benchmark(WAF|Rules)$' -benchmem ./edge/internal/waf ./edge/internal/rules`.

Đây là baseline microbenchmark trên Go mới hơn mức yêu cầu tương thích 1.22.8; race test chưa chạy được trong session này do WSL trả `E_ACCESSDENIED` và Windows host thiếu CGO, vì vậy chưa có số đo/kiểm chứng Go 1.22.8 tại đây.

## WAF managed rules — P4 lượt 2 — 2026-11-22

Đo trên Windows amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz; median của 5 lần chạy `-benchmem`. Bộ luật nhúng có 19 rule. Cả hai benchmark cấu hình ngân sách WAF 2 ms.

| Benchmark | Median ns/op | B/op | allocs/op | Request |
| --- | ---: | ---: | ---: | --- |
| `BenchmarkWAFManagedClean` | 25,462 | 6,831 | 28 | GET tìm kiếm sạch, toàn bộ managed rules ở paranoia 1 |
| `BenchmarkWAFManagedEarlyExit` | 10,134 | 7,093 | 38 | GET có `UNION SELECT`, sensitivity high, dừng khi đạt ngưỡng |

Lệnh đo: `go test -run '^$' -bench '^BenchmarkWAFManaged(Clean|EarlyExit)$' -benchmem ./edge/internal/waf -count=5`.

### Đo TPR/FPR trên corpus tự viết

Lệnh: `go test -count=1 -v ./edge/internal/waf -run TestManagedCorpusTPRFPR`. Attack corpus có 20 mẫu mỗi nhóm (deserialization có 21), clean corpus có 46 mẫu. TPR được đo ở từng paranoia, trên các rule match chứ không dựa vào action block; baseline trong `test/corpus/waf/tpr-baseline.json` được khóa theo lần đo này. TPR dưới baseline làm test đỏ. Mức `WAF_TPR_MIN` (phân số 0..1, mặc định 0) có thể tăng thêm mức tối thiểu; nó không thể hạ baseline đã ghi. `WAF_FPR_MAX` (phân số 0..1, mặc định 0) cấu hình trần FPR; paranoia 1 vượt trần làm test đỏ.

| Nhóm tấn công | Mẫu | P1 | P2 | P3 | P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| SQLi | 20 | 100% | 100% | 100% | 100% |
| XSS | 20 | 100% | 100% | 100% | 100% |
| Path traversal/LFI | 20 | 100% | 100% | 100% | 100% |
| RFI | 20 | 100% | 100% | 100% | 100% |
| RCE/command injection | 20 | 100% | 100% | 100% | 100% |
| SSRF/private & metadata | 20 | 100% | 100% | 100% | 100% |
| XXE | 20 | 100% | 100% | 100% | 100% |
| SSTI | 20 | 100% | 100% | 100% | 100% |
| Deserialization | 21 | 100% | 100% | 100% | 100% |
| Protocol anomaly/smuggling | 20 | 100% | 100% | 100% | 100% |
| Scanner User-Agent | 20 | 100% | 100% | 100% | 100% |
| Sensitive files | 20 | 100% | 100% | 100% | 100% |
| Virtual patch template marker | 20 | 0% | 0% | 0% | 100% |

| Clean group | Mẫu | FPR P1 | FPR P2 | FPR P3 | FPR P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Form | 10 | 0% | 0% | 0% | 0% |
| JSON | 10 | 0% | 0% | 0% | 0% |
| Search | 10 | 0% | 0% | 0% | 0% |
| Valid paths | 8 | 0% | 0% | 0% | 0% |
| Headers | 3 | 0% | 0% | 0% | 0% |
| Text body | 5 | 0% | 0% | 0% | 0% |

Đây là độ đo trên bộ mẫu ngắn, tự viết để kiểm tra hồi quy; 100% không phải ước lượng tỷ lệ bắt được trên lưu lượng thực tế. Bộ sạch có các từ `select`, `union`, `drop`, tìm kiếm có dấu nháy, tên như `O'Neil`, JSON/form và đường dẫn hợp lệ. Các test né tránh bao gồm URL mã hóa kép, hoa/thường, comment SQL xen kẽ, whitespace lạ, NUL, Unicode và CL+TE.

- TODO-1: so sánh cùng corpus với Coraza + OWASP CRS, ghi phiên bản CRS và TPR/FPR theo nhóm; cần tải/cài dependency từ mạng.
## P5a — TLS fingerprint cost (WSL/Linux)

Command: `go test -run '^$' -bench '^BenchmarkFingerprint(PeekAndCompute|ClientHello)$' -benchtime=1000x -benchmem ./edge/internal/listener`.
Go 1.26.11, linux/amd64, Intel Core i5-11400H:

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkFingerprintClientHello` (parser only) | 5,829 | 818 | 44 |
| `BenchmarkFingerprintPeekAndCompute` (bounded read + fingerprint) | 9,854 | 4,068 | 94 |

Measured on the small synthetic benchmark ClientHello used by the fixture builder; it is a parser/peek microbenchmark, not full TLS handshake throughput.
