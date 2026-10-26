// Command heimdall-probe measures latency from a CPE to internet services.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kgns/heimdall/probe/internal/app"
	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/selftest"
)

var version = "dev"

const usage = `usage: heimdall-probe <command> [flags]

commands:
  run        start measuring (see run -h)
  check      validate the configuration and print the effective targets
  selftest   report host facts the probe depends on
  version    print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "run":
		err = runProbe(ctx, os.Args[2:])
	case "check":
		err = runCheck(ctx, os.Args[2:])
	case "selftest":
		err = runSelftest(ctx, os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadConfig(fs *flag.FlagSet, path string) (config.Config, error) {
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			explicit = true
		}
	})
	return config.Load(path, !explicit)
}

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "configuration file; built-in defaults are used if the default path is missing")
	stdout := fs.Bool("stdout", false, "also print samples to stdout as JSON lines")
	level := fs.String("log-level", "info", "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(*level)); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	cfg, _, err := loadAll(fs, *path)
	if err != nil {
		return err
	}
	if *stdout {
		cfg.Output.Stdout = true
	}
	// The CPE's busybox has no nohup, so the probe is started as a plain
	// background job and must survive the login session ending.
	signal.Ignore(syscall.SIGHUP)
	app.ApplyRuntime(cfg.Runtime, log)
	return app.Run(ctx, cfg, version, app.LiveHost(), log)
}

func runSelftest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	skipDNS := fs.Bool("skip-dns", false, "skip live DNS lookups")
	dnsName := fs.String("dns-name", "www.google.com.", "name used for live DNS lookups")
	dnsTimeout := fs.Duration("dns-timeout", 3*time.Second, "timeout per live DNS lookup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d := selftest.HostDeps()
	d.SkipDNS = *skipDNS
	d.DNSName = *dnsName
	d.DNSTimeout = *dnsTimeout

	r := selftest.Run(ctx, version, d)
	if *asJSON {
		return r.WriteJSON(os.Stdout)
	}
	return r.WriteText(os.Stdout)
}
