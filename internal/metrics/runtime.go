package metrics

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// RuntimeGauges are the numbers that show a leak or a stall of the process itself: goroutines, the heap, the memory the process holds, the open file descriptors, the garbage
// collections. They say nothing about what the service decides, and no peer can influence a label (there are none).
func RuntimeGauges() []Gauge {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	g := []Gauge{
		{Name: "hsmgate_go_goroutines", Help: "Goroutines now.", Value: float64(runtime.NumGoroutine())},
		{Name: "hsmgate_go_heap_alloc_bytes", Help: "Bytes of live heap objects.", Value: float64(m.HeapAlloc)},
		{Name: "hsmgate_go_heap_inuse_bytes", Help: "Bytes of heap spans in use.", Value: float64(m.HeapInuse)},
		{Name: "hsmgate_go_sys_bytes", Help: "Bytes obtained from the operating system by the Go runtime.", Value: float64(m.Sys)},
		{Name: "hsmgate_go_gc_cycles", Help: "Completed garbage collections.", Value: float64(m.NumGC)},
	}
	if rss, ok := residentBytes(); ok {
		g = append(g, Gauge{Name: "hsmgate_process_resident_bytes", Help: "Resident memory of the process.", Value: rss})
	}
	if n, ok := openFDs(); ok {
		g = append(g, Gauge{Name: "hsmgate_process_open_fds", Help: "Open file descriptors.", Value: float64(n)})
	}
	return g
}

// residentBytes reads the resident set from /proc/self/statm (Linux; elsewhere the gauge is left out).
func residentBytes() (float64, bool) {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(pages) * float64(os.Getpagesize()), true
}

func openFDs() (int, bool) {
	d, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(d), true
}
