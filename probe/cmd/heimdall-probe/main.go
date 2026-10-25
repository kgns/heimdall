// Command heimdall-probe measures latency from a CPE to internet services.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kgns/heimdall/probe/internal/selftest"
)

var version = "dev"

const usage = `usage: heimdall-probe <command> [flags]

commands:
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
