//go:build perf

package waf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

const cpuScanGateMultiple = 10
const nonOverloadedWallGateMultiple = 5

// Historical request-start wall p99 baselines on GitHub's 4-CPU runner.
var githubWallBaselinesNS = map[string]int64{
	"gomaxprocs_2/workers_200": 30_000_000,
	"gomaxprocs_4/workers_200": 48_000_000,
}

type perfRun struct {
	OS                string `json:"os"`
	Runner            string `json:"runner"`
	CPUs              int    `json:"cpus"`
	GOMAXPROCS        int    `json:"gomaxprocs"`
	Goroutines        int    `json:"goroutines"`
	Cell              string `json:"cell"`
	RequestP50NS      int64  `json:"request_p50_ns"`
	RequestP99NS      int64  `json:"request_p99_ns"`
	ScanCPUP50NS      int64  `json:"scan_cpu_p50_ns"`
	ScanCPUP99NS      int64  `json:"scan_cpu_p99_ns"`
	BaselineWallP99NS int64  `json:"baseline_wall_p99_ns"`
	BaselineCPUP99NS  int64  `json:"baseline_scan_cpu_p99_ns"`
	CleanRejected     int64  `json:"clean_rejected"`
	CleanTotal        int64  `json:"clean_total"`
	AttacksBlocked    int64  `json:"attacks_blocked"`
	AttackTotal       int64  `json:"attack_total"`
	FuseTrips         int64  `json:"fuse_trips"`
	FuseTotal         int64  `json:"fuse_total"`
}

var perfResults struct {
	sync.Mutex
	runs []perfRun
}
var perfExitCode atomic.Int32

func recordPerfRun(result perfRun) {
	perfResults.Lock()
	perfResults.runs = append(perfResults.runs, result)
	perfResults.Unlock()
}

func TestMain(m *testing.M) {
	path := os.Getenv("WAF_PERF_RESULTS")
	if path == "" {
		path = "perf-results.json"
	}
	_ = os.Remove(path)
	code := m.Run()
	perfResults.Lock()
	runs := append([]perfRun(nil), perfResults.runs...)
	perfResults.Unlock()
	data, err := json.MarshalIndent(runs, "", "  ")
	if err == nil {
		err = os.MkdirAll(filepath.Dir(path), 0o755)
	}
	if err == nil {
		err = os.WriteFile(path, data, 0o644)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "write perf artifact: %v\n", err)
		code = 1
	}
	summary := os.Getenv("GITHUB_STEP_SUMMARY")
	if summary == "" {
		summary = filepath.Join(os.TempDir(), "waf-perf-summary.md")
		defer os.Remove(summary)
	}
	if err := writePerfSummary(summary, runs); err != nil {
		fmt.Fprintf(os.Stderr, "write perf summary: %v\n", err)
		code = 1
	}
	if perfExitCode.Load() != 0 {
		code = 1
	}
	os.Exit(code)
}

func writePerfSummary(path string, runs []perfRun) error {
	groups := make(map[string][]perfRun)
	for _, run := range runs {
		groups[run.Cell] = append(groups[run.Cell], run)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintln(f, "\n### WAF perf matrix (p50/p99 median across repetitions)")
	fmt.Fprintln(f, "| Cell | Runner | OS | CPUs | GOMAXPROCS | Goroutines | Runs | request p50 | request p99 | scan CPU p50 | scan CPU p99 | clean rejects | attacks blocked | fuse | latency gate | baseline warning |")
	fmt.Fprintln(f, "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|")
	cells := make([]string, 0, len(groups))
	for cell := range groups {
		cells = append(cells, cell)
	}
	sort.Strings(cells)
	for _, cell := range cells {
		cellRuns := groups[cell]
		medianField := func(value func(perfRun) int64) int64 {
			values := make([]int64, 0, len(cellRuns))
			for _, run := range cellRuns {
				values = append(values, value(run))
			}
			sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
			return values[len(values)/2]
		}
		median := cellRuns[len(cellRuns)/2]
		requestP50 := medianField(func(r perfRun) int64 { return r.RequestP50NS })
		requestP99 := medianField(func(r perfRun) int64 { return r.RequestP99NS })
		cpuP50 := medianField(func(r perfRun) int64 { return r.ScanCPUP50NS })
		cpuP99 := medianField(func(r perfRun) int64 { return r.ScanCPUP99NS })
		cpuBaseline := medianField(func(r perfRun) int64 { return r.BaselineCPUP99NS })
		cpuGate := cpuBaseline * cpuScanGateMultiple
		if cpuP99 > cpuGate {
			fmt.Fprintf(os.Stderr, "scan CPU p99 regression: cell=%s median=%d ns gate=%d ns\n", cell, cpuP99, cpuGate)
			perfExitCode.Store(1)
		}
		gateLabel := fmt.Sprintf("scan CPU %s (10x serial p99)", time.Duration(cpuGate))
		if median.Goroutines <= median.CPUs {
			wallBaseline := medianField(func(r perfRun) int64 { return r.BaselineWallP99NS })
			wallGate := wallBaseline * nonOverloadedWallGateMultiple
			gateLabel += fmt.Sprintf("; wall %s (5x baseline)", time.Duration(wallGate))
			if requestP99 > wallGate {
				fmt.Fprintf(os.Stderr, "non-overloaded request p99 regression: cell=%s median=%d ns gate=%d ns\n", cell, requestP99, wallGate)
				perfExitCode.Store(1)
			}
		} else {
			gateLabel += "; wall-clock informational (overloaded)"
		}
		warning := "no historical cell baseline"
		if base, ok := githubWallBaselinesNS[cell]; ok {
			if requestP99 > base*2 {
				warning = "WARNING >2x baseline"
			} else {
				warning = "within 2x baseline"
			}
		}
		var cleanRejected, cleanTotal, attacksBlocked, attackTotal, fuseTrips, fuseTotal int64
		for _, run := range cellRuns {
			cleanRejected += run.CleanRejected
			cleanTotal += run.CleanTotal
			attacksBlocked += run.AttacksBlocked
			attackTotal += run.AttackTotal
			fuseTrips += run.FuseTrips
			fuseTotal += run.FuseTotal
		}
		fmt.Fprintf(f, "| %s | %s | %s | %d | %d | %d | %d | %s | %s | %s | %s | %d/%d | %d/%d | %d/%d | %s | %s |\n",
			cell, median.Runner, median.OS, median.CPUs, median.GOMAXPROCS, median.Goroutines, len(cellRuns),
			time.Duration(requestP50), time.Duration(requestP99), time.Duration(cpuP50), time.Duration(cpuP99),
			cleanRejected, cleanTotal, attacksBlocked, attackTotal, fuseTrips, fuseTotal, gateLabel, warning)
	}
	return nil
}

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
				baselineWall, baselineCPU := serialScanP99(phase)
				const each = 5
				var wg sync.WaitGroup
				var cleanRejects, attacksCaught, fuseTrips atomic.Int64
				failures := make(chan string, workers*each)
				latencies := make(chan int64, workers*each)
				scanCPUs := make(chan int64, workers*each)
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
							c := makePerfContext(body, mode)
							var d reqctx.Decision
							wall, cpu := measurePerfScan(func() { d = phase.Handle(c) })
							latencies <- wall.Nanoseconds()
							scanCPUs <- cpu.Nanoseconds()
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
				close(scanCPUs)
				for failure := range failures {
					t.Error(failure)
				}
				if got, want := cleanRejects.Load(), int64(0); got != want {
					t.Errorf("clean fail-closed rejects=%d want=%d", got, want)
				}
				if got, want := attacksCaught.Load(), int64(workers); got != want {
					t.Errorf("in-scope attacks blocked=%d want=%d; fuse trips=%d", got, want, fuseTrips.Load())
				}
				if got := fuseTrips.Load(); got != 0 {
					t.Errorf("fuse trips=%d want=0", got)
				}
				samples := make([]int64, 0, workers*each)
				for sample := range latencies {
					samples = append(samples, sample)
				}
				sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
				p50, p99 := samples[len(samples)/2], samples[(len(samples)*99+99)/100-1]
				cpuSamples := make([]int64, 0, workers*each)
				for sample := range scanCPUs {
					cpuSamples = append(cpuSamples, sample)
				}
				sort.Slice(cpuSamples, func(i, j int) bool { return cpuSamples[i] < cpuSamples[j] })
				cpuP50, cpuP99 := cpuSamples[len(cpuSamples)/2], cpuSamples[(len(cpuSamples)*99+99)/100-1]
				cell := fmt.Sprintf("gomaxprocs_%d/workers_%d", n, workers)
				run := perfRun{OS: runtime.GOOS, Runner: perfRunner(), CPUs: runtime.NumCPU(), GOMAXPROCS: n, Goroutines: workers, Cell: cell,
					RequestP50NS: p50, RequestP99NS: p99, ScanCPUP50NS: cpuP50, ScanCPUP99NS: cpuP99, BaselineCPUP99NS: baselineCPU,
					CleanRejected: cleanRejects.Load(), CleanTotal: int64(workers * (each - 1)), AttacksBlocked: attacksCaught.Load(), AttackTotal: int64(workers), FuseTrips: fuseTrips.Load(), FuseTotal: int64(workers * each)}
				run.BaselineWallP99NS = baselineWall
				recordPerfRun(run)
				t.Logf("runner=%s OS=%s CPUs=%d nproc=%s GOMAXPROCS=%d goroutines=%d clean_rejected=%d/%d attacks_blocked=%d/%d fuse=%d/%d request_p50_ns=%d request_p99_ns=%d scan_cpu_p50_ns=%d scan_cpu_p99_ns=%d serial_scan_cpu_p99_ns=%d scan_cpu_gate_ns=%d", run.Runner, run.OS, run.CPUs, os.Getenv("WAF_PERF_NPROC"), n, workers, run.CleanRejected, run.CleanTotal, run.AttacksBlocked, run.AttackTotal, run.FuseTrips, run.FuseTotal, p50, p99, cpuP50, cpuP99, baselineCPU, baselineCPU*cpuScanGateMultiple)
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
	baselineWall, baselineCPU := serialScanP99(phase)
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
	scanCPUs := make(chan int64, workers*each)
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
				ctx := makePerfContext(body, "block")
				var d reqctx.Decision
				wall, cpu := measurePerfScan(func() { d = phase.Handle(ctx) })
				latencies <- wall.Nanoseconds()
				scanCPUs <- cpu.Nanoseconds()
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
	close(scanCPUs)
	for failure := range failures {
		t.Error(failure)
	}
	if got, want := cleanRejected.Load(), int64(0); got != want {
		t.Errorf("GOMAXPROCS=1 CPU-background clean requests rejected=%d want=%d", got, want)
	}
	if got, want := attacksCaught.Load(), int64(workers); got != want {
		t.Errorf("GOMAXPROCS=1 CPU-background attacks blocked=%d want=%d; fuse=%d", got, want, fuseTrips.Load())
	}
	if got := fuseTrips.Load(); got != 0 {
		t.Errorf("GOMAXPROCS=1 CPU-background fuse trips=%d want=0", got)
	}
	if backgroundProgress.Load() == 0 {
		t.Error("CPU background worker did not execute")
	}
	samples := make([]int64, 0, workers)
	for sample := range latencies {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50, p99 := samples[len(samples)/2], samples[(len(samples)*99+99)/100-1]
	cpuSamples := make([]int64, 0, workers*each)
	for sample := range scanCPUs {
		cpuSamples = append(cpuSamples, sample)
	}
	sort.Slice(cpuSamples, func(i, j int) bool { return cpuSamples[i] < cpuSamples[j] })
	cpuP50, cpuP99 := cpuSamples[len(cpuSamples)/2], cpuSamples[(len(cpuSamples)*99+99)/100-1]
	run := perfRun{OS: runtime.GOOS, Runner: perfRunner(), CPUs: runtime.NumCPU(), GOMAXPROCS: 1, Goroutines: workers,
		Cell: "cpu_background/gomaxprocs_1/workers_200", RequestP50NS: p50, RequestP99NS: p99, ScanCPUP50NS: cpuP50, ScanCPUP99NS: cpuP99, BaselineWallP99NS: baselineWall, BaselineCPUP99NS: baselineCPU,
		CleanRejected: cleanRejected.Load(), CleanTotal: workers * (each - 1), AttacksBlocked: attacksCaught.Load(), AttackTotal: workers, FuseTrips: fuseTrips.Load(), FuseTotal: workers * each}
	recordPerfRun(run)
	t.Logf("runner=%s OS=%s CPUs=%d nproc=%s GOMAXPROCS=1 goroutines=%d background_cpu_workers=1 background_iterations=%d clean_rejected=%d/%d attacks_blocked=%d/%d fuse=%d/%d request_p50_ns=%d request_p99_ns=%d scan_cpu_p50_ns=%d scan_cpu_p99_ns=%d serial_scan_cpu_p99_ns=%d scan_cpu_gate_ns=%d", run.Runner, run.OS, run.CPUs, os.Getenv("WAF_PERF_NPROC"), workers, backgroundProgress.Load(), run.CleanRejected, run.CleanTotal, run.AttacksBlocked, run.AttackTotal, run.FuseTrips, run.FuseTotal, p50, p99, cpuP50, cpuP99, baselineCPU, baselineCPU*cpuScanGateMultiple)
}

func makePerfContext(body, mode string) *reqctx.RequestCtx {
	r := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	c := reqctx.New(r, nil, "perf-load", nil)
	c.Site = &wafcore.Site{ID: "perf", Plan: "enterprise", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: mode, Sensitivity: "high", Paranoia: 4, BodyLimitKB: 8}}
	return c
}

func serialScanP99(phase *Phase) (int64, int64) {
	const samples = 128
	wallTimes := make([]int64, 0, samples)
	cpuTimes := make([]int64, 0, samples)
	for i := 0; i < samples; i++ {
		ctx := makePerfContext(`{"q":"ordinary documentation `+strings.Repeat("safe ", 200)+`"}`, "block")
		wall, cpu := measurePerfScan(func() { _ = phase.Handle(ctx) })
		wallTimes = append(wallTimes, wall.Nanoseconds())
		cpuTimes = append(cpuTimes, cpu.Nanoseconds())
		reqctx.Release(ctx)
	}
	percentile99 := func(times []int64) int64 {
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		return times[(len(times)*99+99)/100-1]
	}
	return percentile99(wallTimes), percentile99(cpuTimes)
}

func perfRunner() string {
	if runner := os.Getenv("WAF_PERF_RUNNER"); runner != "" {
		return runner
	}
	return "local"
}
