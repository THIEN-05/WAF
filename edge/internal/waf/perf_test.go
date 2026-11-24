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

const perfP99Gate = 69 * time.Millisecond // 3 × the user-measured 23 ms worst cell.

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
							requestStarted := time.Now() // request arrival at the WAF handler; excludes time queued before the goroutine runs.
							d := phase.Handle(c)
							latencies <- time.Since(requestStarted).Nanoseconds()
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
				if time.Duration(p99) > perfP99Gate {
					t.Errorf("request-start p99=%s exceeds wide regression gate %s", time.Duration(p99), perfP99Gate)
				}
				t.Logf("OS=%s CPUs=%d GOMAXPROCS=%d goroutines=%d clean_rejected=%d/%d attacks_blocked=%d/%d fuse=%d/%d request_start_p50_ns=%d request_start_p99_ns=%d p99_gate_ns=%d", runtime.GOOS, runtime.NumCPU(), n, workers, cleanRejects.Load(), workers*each-workers, attacksCaught.Load(), workers, fuseTrips.Load(), workers*each, p50, p99, perfP99Gate.Nanoseconds())
			})
		}
	}
}

func TestWAFCleanFailClosedAtOnePWithCPUBackground(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(original)

	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var runBackground atomic.Bool
	var backgroundProgress atomic.Uint64
	backgroundReady := make(chan struct{})
	var backgroundWG sync.WaitGroup
	runBackground.Store(true)
	backgroundWG.Add(1)
	go func() {
		defer backgroundWG.Done()
		close(backgroundReady)
		var n uint64
		for runBackground.Load() {
			n++
			if n&0x3fff == 0 {
				backgroundProgress.Store(n)
			}
		}
	}()
	<-backgroundReady
	const workers, each = 200, 5
	var wg sync.WaitGroup
	var cleanRejected, attacksCaught, fuseTrips atomic.Int64
	failures := make(chan string, workers*each)
	latencies := make(chan int64, workers*each)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				attack := i == 0
				body := `{"q":"ordinary documentation ` + strings.Repeat("safe ", 200) + `"}`
				if attack {
					body = `{"q":"UNION SELECT password FROM users","padding":"` + strings.Repeat("safe ", 200) + `"}`
				}
				r := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				ctx := reqctx.New(r, nil, "cpu-background", nil)
				ctx.Site = &wafcore.Site{ID: "perf", Plan: "enterprise", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 4, BodyLimitKB: 8}}
				requestStarted := time.Now()
				d := phase.Handle(ctx)
				latencies <- time.Since(requestStarted).Nanoseconds()
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
					cleanRejected.Add(1)
					failures <- fmt.Sprintf("clean request=%d action=%v rule=%s score=%d reason=%q tags=%v", worker, d.Action, d.RuleID, d.Score, d.Reason, d.Tags)
				}
				reqctx.Release(ctx)
			}
		}(worker)
	}
	wg.Wait()
	runBackground.Store(false)
	backgroundWG.Wait()
	close(failures)
	close(latencies)
	for failure := range failures {
		t.Error(failure)
	}
	if got, want := cleanRejected.Load(), int64(0); got != want {
		t.Errorf("GOMAXPROCS=1 CPU-background clean requests rejected=%d want=%d", got, want)
	}
	if got, want := attacksCaught.Load(), int64(workers); got != want {
		t.Errorf("GOMAXPROCS=1 CPU-background attacks blocked=%d want=%d; fuse=%d", got, want, fuseTrips.Load())
	}
	if backgroundProgress.Load() == 0 {
		t.Error("CPU background worker did not execute")
	}
	samples := make([]int64, 0, workers)
	for sample := range latencies {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p99 := samples[(len(samples)*99+99)/100-1]
	if time.Duration(p99) > perfP99Gate {
		t.Errorf("CPU-background request-start p99=%s exceeds wide regression gate %s", time.Duration(p99), perfP99Gate)
	}
	t.Logf("OS=%s CPUs=%d GOMAXPROCS=1 goroutines=%d background_cpu_workers=1 background_iterations=%d clean_rejected=%d/%d attacks_blocked=%d/%d fuse=%d/%d request_start_p50_ns=%d request_start_p99_ns=%d p99_gate_ns=%d", runtime.GOOS, runtime.NumCPU(), workers, backgroundProgress.Load(), cleanRejected.Load(), workers*(each-1), attacksCaught.Load(), workers, fuseTrips.Load(), workers*each, samples[len(samples)/2], p99, perfP99Gate.Nanoseconds())
}
