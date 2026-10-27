// Command heimdall-client measures from a laptop on the LAN for a limited
// time, so its numbers can be compared with what the CPE's probe sees
// about the same machine: the round trip to the CPE, TCP connection setup
// to the services the CPE measures, and the laptop's own Wi-Fi link.
//
//	heimdall-client -device mbp-kgns -duration 30m
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kgns/heimdall/probe/internal/client"
	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/resolve"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/uploader"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	home, _ := os.UserHomeDir()
	device := flag.String("device", "", "device ID registered with the ingest API (required)")
	tokenFile := flag.String("token-file", filepath.Join(home, ".config", "heimdall", "token"), "file holding the device's upload token")
	url := flag.String("url", "https://ingest.lat.kgns.dev/v1/batch", "ingest API URL")
	duration := flag.Duration("duration", 30*time.Minute, "how long to measure; 0 runs until interrupted")
	interval := flag.Duration("interval", 10*time.Second, "TCP connects to each target")
	pingInterval := flag.Duration("ping-interval", time.Second, "ICMP and TCP to the CPE")
	wifiInterval := flag.Duration("wifi-interval", 30*time.Second, "Wi-Fi link readings (macOS)")
	targets := flag.String("targets", "", "service=host[:port],... instead of the built-in list")
	stdout := flag.Bool("stdout", false, "also print samples as JSON lines")
	noUpload := flag.Bool("no-upload", false, "do not upload; implies -stdout")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *device == "" {
		return errors.New("-device is required")
	}
	if *interval < time.Second || *pingInterval < 200*time.Millisecond {
		return errors.New("-interval must be at least 1s and -ping-interval at least 200ms")
	}
	tl := client.DefaultTargets()
	if *targets != "" {
		var err error
		if tl, err = parseTargets(*targets); err != nil {
			return err
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	var sinks []sample.Sink
	if *stdout || *noUpload {
		sinks = append(sinks, sample.NewStreamSink(os.Stdout))
	}
	var up *uploader.Uploader
	var buf *uploader.Buffer
	if !*noUpload {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("upload token: %w", err)
		}
		buf = uploader.NewBuffer(8 << 20)
		sinks = append(sinks, buf)
		up, err = uploader.New(buf, uploader.Options{
			URL: *url, Token: strings.TrimSpace(string(b)), Device: *device, ProbeVersion: "client-" + version,
			Interval: 10 * time.Second, Timeout: 15 * time.Second, MaxBatch: 2000, MaxBatchBytes: 2 << 20,
			MinBackoff: 5 * time.Second, MaxBackoff: time.Minute, Lookup: resolve.SystemLookup,
			Log: log, DrainAfterStop: 10 * time.Second,
		})
		if err != nil {
			return err
		}
	}
	rec := sample.NewRecorder(*device, time.Now, sinks...)
	defer rec.Close()

	var pinger *icmp.Pinger
	if conn, err := icmp.Listen(icmp.ModeDgram); err != nil {
		log.Warn("no ICMP socket; the CPE is measured over TCP only", "err", err)
	} else if pinger, err = icmp.New(conn, icmp.Options{PayloadSize: 32}); err != nil {
		conn.Close()
		log.Warn("no ICMP pinger", "err", err)
		pinger = nil
	}
	if pinger != nil {
		defer pinger.Close()
	}

	runID := ""
	upDone := make(chan struct{})
	upCtx, stopUpload := context.WithCancel(context.Background())
	defer stopUpload()
	if up != nil {
		runID = up.RunID()
		go func() { defer close(upDone); up.Run(upCtx) }()
	} else {
		close(upDone)
	}
	gw, _ := client.Gateway()
	hostname, _ := os.Hostname()
	rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Extra: map[string]any{
		"event": "start", "version": version, "client": true, "run_id": runID, "gateway": gw.String(),
		"hostname": config.DeviceFromHostname(hostname), "targets": len(tl), "icmp": pinger != nil,
	}})
	log.Info("measuring", "device", *device, "gateway", gw, "targets", len(tl), "duration", *duration, "upload", up != nil)

	c := client.New(client.Options{
		Targets: tl, Interval: *interval, PingInterval: *pingInterval, WiFiInterval: *wifiInterval,
		Emit: rec.Emit, Lookup: resolve.SystemLookup, Gateway: client.Gateway, Pinger: pinger, WiFi: client.ReadWiFi,
	})
	hb := time.NewTicker(time.Minute)
	defer hb.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hb.C:
				x := map[string]any{"version": version, "run_id": runID}
				if up != nil {
					x["upload"], x["buffer"] = up.Status(), buf.Stats()
				}
				rec.Emit(sample.Sample{Kind: sample.KindHeartbeat, Status: sample.StatusOK, Extra: x})
			}
		}
	}()
	c.Run(ctx)

	rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Extra: map[string]any{"event": "stop", "client": true}})
	stopUpload()
	<-upDone
	if up != nil {
		log.Info("done", "upload", up.Status(), "unsent", buf.Stats().Samples)
	}
	return nil
}

func parseTargets(s string) ([]client.Target, error) {
	var out []client.Target
	for _, item := range strings.Split(s, ",") {
		svc, hp, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok || svc == "" || hp == "" {
			return nil, fmt.Errorf("target %q: want service=host[:port]", item)
		}
		t := client.Target{Service: svc, Category: "unclassified", Host: hp, Port: 443}
		if h, p, ok := strings.Cut(hp, ":"); ok {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("target %q: bad port", item)
			}
			t.Host, t.Port = h, n
		}
		if !config.ValidHost(t.Host) {
			return nil, fmt.Errorf("target %q: bad host", item)
		}
		out = append(out, t)
	}
	return out, nil
}
