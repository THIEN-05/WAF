//go:build perf && linux

package waf

import (
	"runtime"
	"syscall"
	"time"
)

func measurePerfScan(run func()) (wall, cpu time.Duration) {
	runtime.LockOSThread()
	startCPU := threadCPUTime()
	start := time.Now()
	run()
	wall = time.Since(start)
	cpu = threadCPUTime() - startCPU
	runtime.UnlockOSThread()
	return wall, cpu
}

func threadCPUTime() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(1, &usage); err != nil { // RUSAGE_THREAD
		return 0
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second +
		time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond
}
