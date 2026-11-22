# Benchmark

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
