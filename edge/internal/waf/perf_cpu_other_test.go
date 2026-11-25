//go:build perf && !linux

package waf

import "time"

// Non-Linux runs retain elapsed duration for local diagnostics. CI's Linux
// runner uses per-thread CPU time and therefore excludes scheduler wait.
func measurePerfScan(run func()) (wall, cpu time.Duration) {
	start := time.Now()
	run()
	wall = time.Since(start)
	return wall, wall
}
