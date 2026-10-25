package app

import (
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/kgns/heimdall/probe/internal/config"
)

// ApplyRuntime sets GOMAXPROCS, the soft memory limit and the process nice
// value. GOMAXPROCS and GOMEMLIMIT from the environment win over the
// configuration.
func ApplyRuntime(rt config.Runtime, log *slog.Logger) {
	if os.Getenv("GOMAXPROCS") == "" && rt.GOMAXPROCS > 0 {
		runtime.GOMAXPROCS(rt.GOMAXPROCS)
	}
	if os.Getenv("GOMEMLIMIT") == "" && rt.MemoryLimit > 0 {
		debug.SetMemoryLimit(int64(rt.MemoryLimit))
	}
	if rt.Nice > 0 {
		if err := renice(rt.Nice); err != nil {
			log.Warn("could not lower process priority", "nice", rt.Nice, "err", err)
		}
	}
}
