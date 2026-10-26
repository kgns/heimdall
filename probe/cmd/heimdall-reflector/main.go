// Command heimdall-reflector is the cloud end of heimdall's measurements.
// It runs a STAMP session-reflector (RFC 8762), a TCP port that accepts and
// closes connections, and the authoritative server of the whoami zone that
// tells probes which resolver is answering for them.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/probes/stamp"
	"github.com/kgns/heimdall/probe/internal/whoami"
)

var version = "dev"

func main() {
	var (
		stampAddr  = flag.String("stamp", fmt.Sprintf(":%d", stamp.Port), "STAMP reflector UDP address; empty disables")
		tcpAddr    = flag.String("tcp", ":443", "TCP accept-and-close address; empty disables")
		dnsAddr    = flag.String("dns", ":53", "whoami DNS address (UDP and TCP); empty disables")
		zone       = flag.String("zone", "w.lat.kgns.dev", "whoami zone apex")
		ns         = flag.String("ns", "ns.lat.kgns.dev", "name server host of the zone")
		hostmaster = flag.String("hostmaster", "hostmaster.kgns.dev", "SOA RNAME of the zone")
		statsEvery = flag.Duration("stats", time.Minute, "interval of the stats log line")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, *stampAddr, *tcpAddr, *dnsAddr, *zone, *ns, *hostmaster, *statsEvery); err != nil {
		log.Error("reflector failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, stampAddr, tcpAddr, dnsAddr, zone, ns, hostmaster string, statsEvery time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 4)
	stats := map[string]func() any{}

	if stampAddr != "" {
		pc, err := net.ListenPacket("udp4", stampAddr)
		if err != nil {
			return fmt.Errorf("stamp: %w", err)
		}
		r := stamp.NewReflector()
		stats["stamp"] = func() any { return r.Stats() }
		go func() { errc <- r.Serve(ctx, pc) }()
	}
	if tcpAddr != "" {
		ln, err := net.Listen("tcp4", tcpAddr)
		if err != nil {
			return fmt.Errorf("tcp: %w", err)
		}
		var accepted atomic.Uint64
		stats["tcp"] = func() any { return map[string]uint64{"accepted": accepted.Load()} }
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						errc <- nil
						return
					}
					time.Sleep(10 * time.Millisecond)
					continue
				}
				accepted.Add(1)
				c.Close()
			}
		}()
	}
	if dnsAddr != "" {
		z := whoami.New(zone, ns, hostmaster)
		stats["dns"] = func() any { return z.Stats() }
		for _, netw := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: dnsAddr, Net: netw, Handler: z, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
			started := make(chan error, 1)
			srv.NotifyStartedFunc = func() { started <- nil }
			go func() {
				if err := srv.ListenAndServe(); err != nil {
					started <- err
					errc <- fmt.Errorf("dns/%s: %w", netw, err)
				}
			}()
			if err := <-started; err != nil {
				return fmt.Errorf("dns/%s: %w", netw, err)
			}
			go func() {
				<-ctx.Done()
				_ = srv.Shutdown()
			}()
		}
	}
	log.Info("reflector started", "version", version, "stamp", stampAddr, "tcp", tcpAddr, "dns", dnsAddr, "zone", zone)

	t := time.NewTicker(statsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("reflector stopped")
			return nil
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-t.C:
			snap := map[string]any{}
			for k, f := range stats {
				snap[k] = f()
			}
			b, _ := json.Marshal(snap)
			log.Info("stats", "counters", string(b))
		}
	}
}
