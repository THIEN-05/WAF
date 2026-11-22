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
