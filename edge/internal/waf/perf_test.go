//go:build perf

package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

// This wall-clock load test runs in the required perf CI job without -race.
// Deterministic WAF policy tests remain in the default race suite.
func TestWAFParallel50GOMAXPROCSMatrix(t *testing.T) {
	procs := []int{1, 2, 4, runtime.NumCPU()}
	seen := map[int]bool{}
	for _, n := range procs {
		if n < 1 || seen[n] {
			continue
		}
		seen[n] = true
		for _, workers := range []int{50, 200} {
			t.Run(fmt.Sprintf("gomaxprocs_%d/workers_%d", n, workers), func(t *testing.T) {
				original := runtime.GOMAXPROCS(0)
				runtime.GOMAXPROCS(n)
				defer runtime.GOMAXPROCS(original)

				phase, err := NewPhase(loadManagedRules(t), nil)
				if err != nil {
					t.Fatal(err)
				}
				const each = 5
				var wg sync.WaitGroup
				var cleanRejects, attacksCaught, fuseTrips atomic.Int64
				failures := make(chan string, workers*each)
				latencies := make(chan int64, workers*each)
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func(worker int) {
						defer wg.Done()
						workerStarted := time.Now()
						for i := 0; i < each; i++ {
							attack := i == 0
							body := `{"q":"ordinary documentation ` + strings.Repeat("safe ", 200) + `"}`
							mode := "block"
							if attack {
								body = `{"q":"UNION SELECT password FROM users","padding":"` + strings.Repeat("safe ", 200) + `"}`
							}
							r := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(body))
							r.Header.Set("Content-Type", "application/json")
							c := reqctx.New(r, nil, "perf-load", nil)
							c.Site = &wafcore.Site{ID: "perf", Plan: "enterprise", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: mode, Sensitivity: "high", Paranoia: 4, BodyLimitKB: 8}}
							d := phase.Handle(c)
							if containsString(d.Tags, "waf_budget_exceeded") {
								fuseTrips.Add(1)
							}
							if attack {
								if d.Action == reqctx.ActionBlock && containsString(d.Tags, "sqli") {
									attacksCaught.Add(1)
								} else {
									failures <- fmt.Sprintf("attack request=%d action=%v rule=%s score=%d reason=%q tags=%v", worker, d.Action, d.RuleID, d.Score, d.Reason, d.Tags)
								}
							} else if d.Action == reqctx.ActionBlock {
								cleanRejects.Add(1)
								failures <- fmt.Sprintf("clean request=%d action=%v rule=%s score=%d reason=%q tags=%v", worker, d.Action, d.RuleID, d.Score, d.Reason, d.Tags)
							}
							reqctx.Release(c)
						}
						latencies <- time.Since(workerStarted).Nanoseconds() / each
					}(w)
				}
				wg.Wait()
				close(failures)
				close(latencies)
				for failure := range failures {
					t.Error(failure)
				}
				if got, want := cleanRejects.Load(), int64(0); got != want {
					t.Errorf("clean fail-closed rejects=%d want=%d", got, want)
				}
				if got, want := attacksCaught.Load(), int64(workers); got != want {
					t.Errorf("in-scope attacks blocked=%d want=%d; fuse trips=%d", got, want, fuseTrips.Load())
				}
				samples := make([]int64, 0, workers*each)
				for sample := range latencies {
					samples = append(samples, sample)
				}
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				p50, p99 := samples[len(samples)/2], samples[(len(samples)*99+99)/100-1]
				t.Logf("workers=%d GOMAXPROCS=%d CPUs=%d clean_rejected=%d/%d attacks_blocked=%d/%d fuse=%d/%d worker_mean_request_p50_ns=%d worker_mean_request_p99_ns=%d", workers, n, runtime.NumCPU(), cleanRejects.Load(), workers*each-workers, attacksCaught.Load(), workers, fuseTrips.Load(), workers*each, p50, p99)
			})
		}
	}
}
