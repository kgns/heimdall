package app

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/discover"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/target"
)

func ep(label, addr string) discover.Endpoint {
	return discover.Endpoint{Label: label, Addr: netip.MustParseAddr(addr)}
}

func TestDiscoveryAssign(t *testing.T) {
	cfg := config.Default()
	e, mem := testEnv(t, cfg)
	var slots []*target.Target
	for _, id := range []string{"netflix/netflix_oca/1", "netflix/netflix_oca/2", "netflix/netflix_oca/3"} {
		tg := target.New(id, "streaming", "netflix", netip.Addr{})
		tg.Discovery = "netflix_oca"
		slots = append(slots, tg)
	}
	other := target.New("netflix/www.netflix.com", "streaming", "netflix", netip.MustParseAddr("207.45.72.1"))
	answers := [][]discover.Endpoint{
		{ep("saw001", "195.33.196.5"), ep("teq001", "195.33.196.6"), ep("ank001", "195.33.196.7"), ep("vie001", "45.57.1.1")},
		// saw001 is gone, ank001 moved first, a blocked endpoint appears.
		{ep("ank001", "195.33.196.7"), ep("blocked", "62.58.244.17"), ep("teq001", "195.33.196.6"), ep("adb001", "195.33.196.8")},
		{ep("teq001", "195.33.196.6")},
		nil,
	}
	run := 0
	d := newDiscovery(e, append(slots, other), nil, func(a netip.Addr) bool { return a.String() != "62.58.244.17" }, nil)
	d.run = func(_ context.Context, name string, _ discover.Env) ([]discover.Endpoint, error) {
		if name != "netflix_oca" {
			t.Fatalf("discoverer %q", name)
		}
		defer func() { run++ }()
		if answers[run] == nil {
			return nil, errors.New("api.fast.com: HTTP 503")
		}
		return answers[run], nil
	}
	if len(d.groups) != 1 || len(d.groups[0].slots) != 3 || len(d.jobs()) != 1 {
		t.Fatalf("groups %+v", d.groups)
	}
	labels := func() []string {
		var out []string
		for _, s := range slots {
			l, _ := s.Endpoint()
			out = append(out, l.Label+"@"+s.Addr().String())
		}
		return out
	}
	job := d.jobs()[0]
	job.Run(context.Background())
	if got := labels(); got[0] != "saw001@195.33.196.5" || got[1] != "teq001@195.33.196.6" || got[2] != "ank001@195.33.196.7" {
		t.Fatalf("first %v", got)
	}
	job.Run(context.Background())
	// teq001 and ank001 keep their slots; saw001's slot takes adb001.
	if got := labels(); got[0] != "adb001@195.33.196.8" || got[1] != "teq001@195.33.196.6" || got[2] != "ank001@195.33.196.7" {
		t.Fatalf("second %v", got)
	}
	job.Run(context.Background())
	if got := labels(); got[0] != "@invalid IP" || got[1] != "teq001@195.33.196.6" || got[2] != "@invalid IP" {
		t.Fatalf("third %v", got)
	}
	if _, ok := slots[0].Dst(); ok {
		t.Fatal("cleared slot still has an address")
	}
	job.Run(context.Background())
	// A failed run leaves the slots as they were.
	if got := labels(); got[1] != "teq001@195.33.196.6" {
		t.Fatalf("after failure %v", got)
	}

	var events []sample.Sample
	for _, s := range mem.Samples() {
		if s.Kind == sample.KindEvent && s.Extra["event"] == "discovery" {
			events = append(events, s)
		}
	}
	if len(events) != 4 || events[0].Extra["changed"] != true || events[3].Status != sample.StatusError ||
		len(events[0].Extra["endpoints"].([]map[string]any)) != 3 {
		t.Fatalf("events %+v", events)
	}

	// Samples from a discovered target name the endpoint.
	s := sample.Sample{}
	withEndpoint(slots[1], &s)
	if s.Extra["endpoint"] != "teq001" {
		t.Fatalf("%+v", s)
	}
}
