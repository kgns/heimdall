package discover

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"testing"
)

func TestEncodeSN(t *testing.T) {
	// turkcell-saw6 is the Google Global Cache mapping of a Turkcell
	// Superonline line; lax17s08 is the documented 1e100.net example.
	for in, want := range map[string]string{"turkcell-saw6": "u0g3jxaa-n5fd", "lax": "a5m"} {
		if got := EncodeSN(in); got != want {
			t.Fatalf("EncodeSN(%q) = %q, want %q", in, got, want)
		}
	}
	if m := mappingRE.FindSubmatch([]byte("176.40.225.9 => turkcell-saw6 (176.40.224.0/22)\n")); string(m[1]) != "turkcell-saw6" {
		t.Fatalf("%q", m)
	}
}

func TestDistance(t *testing.T) {
	// Istanbul to Frankfurt is about 1860 km.
	if d := distanceKm(41.01, 28.98, 50.12, 8.68); math.Abs(d-1860) > 30 {
		t.Fatalf("%v", d)
	}
}

func TestSTUNServers(t *testing.T) {
	env := Env{
		STUN: []string{"stun.example.net:19302", "bad.example.net:x", "nodefault.example.net"},
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "stun.example.net" {
				return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("74.125.250.129")}, nil
			}
			return nil, errors.New("nxdomain")
		},
	}
	eps, err := Run(context.Background(), "stun", env)
	if err != nil || len(eps) != 1 || eps[0].Port != 19302 || eps[0].Addr.String() != "74.125.250.129" {
		t.Fatalf("%+v %v", eps, err)
	}
	if _, err := Run(context.Background(), "stun", Env{Lookup: env.Lookup}); err == nil {
		t.Fatal("empty server list accepted")
	}
	if _, err := Run(context.Background(), "riot", env); err == nil {
		t.Fatal("unknown discoverer accepted")
	}
}

func TestGameLift(t *testing.T) {
	env := Env{
		GameLiftRegions: []string{"eu-central-1", "me-central-1"},
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "gamelift-ping.eu-central-1.api.aws" {
				return []netip.Addr{netip.MustParseAddr("3.64.194.36")}, nil
			}
			return nil, nil
		},
	}
	eps, err := Run(context.Background(), "gamelift", env)
	if err != nil || len(eps) != 1 || eps[0].Label != "eu-central-1" {
		t.Fatalf("%+v %v", eps, err)
	}
}
