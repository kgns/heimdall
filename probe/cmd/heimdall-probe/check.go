package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kgns/heimdall/probe/internal/catalog"
	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/netwatch"
	"github.com/kgns/heimdall/probe/internal/resolve"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
	"github.com/kgns/heimdall/probe/internal/target"
)

func runCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "configuration file")
	doResolve := fs.Bool("resolve", false, "resolve hostname targets through the system resolver and apply the route guard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, services, err := loadAll(fs, *path)
	if err != nil {
		return err
	}

	fmt.Printf("config ok: %d targets, %.1f probes/s (budget %.1f)\n", len(cfg.Targets), cfg.ProbeRate(), cfg.Scheduler.MaxPPS)
	if cfg.Catalog.Path != "" {
		fmt.Printf("catalog: %s, regions %v, %d services selected\n", cfg.Catalog.Path, cfg.Catalog.Regions, len(services))
		printNonICMP(services)
	}

	var lookups map[string]resolve.Result
	if *doResolve {
		if lookups, err = resolveAll(ctx, cfg); err != nil {
			return err
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nID\tCATEGORY\tSERVICE\tDESTINATION\tEVERY\tRESOLVED")
	for _, t := range cfg.Targets {
		dst := t.IP
		switch {
		case t.TTL > 0:
			dst = fmt.Sprintf("hop %d via %s", t.TTL, t.IP)
		case t.Auto != "":
			dst = "auto:" + t.Auto
		case t.Host != "":
			dst = t.Host
		}
		resolved := ""
		if r, ok := lookups[t.ID]; ok {
			switch {
			case r.Err != nil:
				resolved = "ERROR " + r.Err.Error()
			case !r.Chosen.IsValid():
				resolved = fmt.Sprintf("NO USABLE ADDRESS %v", r.Answers)
			default:
				resolved = fmt.Sprintf("%s (%d answers, %.0f ms)", r.Chosen, len(r.Answers), sample.Millis(r.Duration))
				if r.Blocked {
					resolved += " BLOCKED by route guard"
				}
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\n", t.ID, t.Category, t.Service, dst, cfg.TargetInterval(t), resolved)
	}
	return tw.Flush()
}

func printNonICMP(services []catalog.Service) {
	var pending []string
	for _, s := range services {
		var what []string
		for _, p := range s.Protocols {
			if p != "icmp" {
				what = append(what, p)
			}
		}
		what = append(what, s.Discovery...)
		if len(what) > 0 {
			pending = append(pending, fmt.Sprintf("%s (%s)", s.ID, strings.Join(what, ", ")))
		}
	}
	if len(pending) > 0 {
		sort.Strings(pending)
		fmt.Printf("not measured by this version yet: %s\n", strings.Join(pending, "; "))
	}
}

// resolveAll resolves every hostname target once, as the probe would at
// startup, and returns the per-target results.
func resolveAll(ctx context.Context, cfg config.Config) (map[string]resolve.Result, error) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	nw := netwatch.New(os.DirFS("/"), sysinfo.LookupInterface, nil, func(sample.Sample) {}, log)
	if _, err := nw.Refresh(); err != nil {
		return nil, err
	}
	res := resolve.New(resolve.SystemLookup, nw.Allowed, func(sample.Sample) {}, log, cfg.Catalog.ResolveTimeout)
	out := map[string]resolve.Result{}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for _, tc := range cfg.Targets {
		if tc.Host == "" {
			continue
		}
		t := target.New(tc.ID, tc.Category, tc.Service, netip.Addr{})
		t.Host = tc.Host
		out[tc.ID] = res.Refresh(ctx, t)
	}
	return out, nil
}

// loadAll loads the configuration and merges in the catalog.
func loadAll(fs *flag.FlagSet, path string) (config.Config, []catalog.Service, error) {
	cfg, err := loadConfig(fs, path)
	if err != nil {
		return cfg, nil, err
	}
	services, err := catalog.Apply(&cfg)
	return cfg, services, err
}
