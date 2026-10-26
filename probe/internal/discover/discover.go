// Package discover finds the servers a service really uses for its
// traffic, beyond the hostnames in the catalog: the video cache a client is
// mapped to, nearby game relays, voice regions and STUN servers. Each
// discoverer asks the service's own public endpoints, from the probe's
// network position, so the answer is what a client on the same line gets.
package discover

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kgns/heimdall/probe/internal/config"
)

// Endpoint is one discovered server.
type Endpoint struct {
	// Label names the server for people: a hostname, a region, a relay.
	Label string
	Addr  netip.Addr
	// Port overrides the protocol's default port for this endpoint.
	Port int
	Meta map[string]any
}

// Spec describes what a discoverer produces: how many endpoints a service
// keeps, and how they are measured.
type Spec struct {
	Slots     int
	Protocols []string
	// Port is the TCP or UDP port the endpoints are measured on.
	Port int
}

// Specs lists the discoverers. riot has no public endpoint that reveals
// game servers, so it is not implemented.
var Specs = map[string]Spec{
	"youtube_cache": {Slots: 2, Protocols: []string{config.ProtoICMP, config.ProtoTCP}, Port: 443},
	"netflix_oca":   {Slots: 3, Protocols: []string{config.ProtoICMP, config.ProtoTCP}, Port: 443},
	"steam_sdr":     {Slots: 3, Protocols: []string{config.ProtoICMP}},
	"gamelift":      {Slots: 4, Protocols: []string{config.ProtoUDP}, Port: 7770},
	"discord_voice": {Slots: 3, Protocols: []string{config.ProtoTCP}, Port: 443},
	"stun":          {Slots: 2, Protocols: []string{config.ProtoSTUN}, Port: 3478},
}

// Env is what discoverers need from the probe.
type Env struct {
	HTTP   *http.Client
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Lat and Lon locate the probe, for choosing nearby relays.
	Lat, Lon float64
	// GameLiftRegions are the AWS regions whose ping beacons are measured.
	GameLiftRegions []string
	// STUN are host:port servers listed by the service in the catalog.
	STUN []string
}

// Run executes discoverer name.
func Run(ctx context.Context, name string, env Env) ([]Endpoint, error) {
	switch name {
	case "youtube_cache":
		return youtubeCache(ctx, env)
	case "netflix_oca":
		return netflixOCA(ctx, env)
	case "steam_sdr":
		return steamSDR(ctx, env)
	case "gamelift":
		return gameLift(ctx, env)
	case "discord_voice":
		return discordVoice(ctx, env)
	case "stun":
		return stunServers(ctx, env)
	}
	return nil, fmt.Errorf("discoverer %q is not implemented", name)
}

const maxBody = 2 << 20

func get(ctx context.Context, c *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; heimdall-probe)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return b, nil
}

// resolve returns the first usable IPv4 address of host.
func resolve(ctx context.Context, env Env, host string) (netip.Addr, error) {
	addrs, err := env.Lookup(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if config.UsableAddr(a) {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s: no public IPv4 address in %v", host, addrs)
}

// YouTube: report_mapping names the cache cluster the client is mapped to,
// for example "turkcell-saw6" (an ISP-hosted Google Global Cache) or
// "fra16s50". Video hostnames encode that name with a fixed substitution:
// rr<n>---sn-<encoded>.googlevideo.com.

var mappingRE = regexp.MustCompile(`=>\s*([a-z0-9-]+)`)

const snTable = "1023456789abcdefghijklmnopqrstuvwxyz"

// EncodeSN applies the googlevideo hostname substitution to a cluster name.
func EncodeSN(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteByte(snTable[((int(r-'a'))*7+5)%36])
		case r >= '0' && r <= '9':
			b.WriteByte(snTable[((int(r-'0')+1)*7)%36])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func youtubeCache(ctx context.Context, env Env) ([]Endpoint, error) {
	b, err := get(ctx, env.HTTP, "https://redirector.googlevideo.com/report_mapping?di=no")
	if err != nil {
		return nil, err
	}
	m := mappingRE.FindSubmatch(b)
	if m == nil {
		return nil, fmt.Errorf("report_mapping: no cluster in %q", strings.TrimSpace(string(b)))
	}
	cluster := string(m[1])
	var out []Endpoint
	var errs []error
	for n := 1; n <= Specs["youtube_cache"].Slots; n++ {
		host := fmt.Sprintf("rr%d---sn-%s.googlevideo.com", n, EncodeSN(cluster))
		a, err := resolve(ctx, env, host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, Endpoint{Label: host, Addr: a, Meta: map[string]any{"cluster": cluster}})
	}
	if len(out) == 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// Netflix: fast.com asks api.fast.com for the Open Connect appliances that
// would serve this client, with a token embedded in its script.

var (
	fastScriptRE = regexp.MustCompile(`app-[a-z0-9]+\.js`)
	fastTokenRE  = regexp.MustCompile(`token:"([A-Za-z0-9]+)"`)
)

func netflixOCA(ctx context.Context, env Env) ([]Endpoint, error) {
	page, err := get(ctx, env.HTTP, "https://fast.com/")
	if err != nil {
		return nil, err
	}
	script := fastScriptRE.Find(page)
	if script == nil {
		return nil, errors.New("fast.com: script not found")
	}
	js, err := get(ctx, env.HTTP, "https://fast.com/"+string(script))
	if err != nil {
		return nil, err
	}
	tok := fastTokenRE.FindSubmatch(js)
	if tok == nil {
		return nil, errors.New("fast.com: token not found")
	}
	u := "https://api.fast.com/netflix/speedtest/v2?https=true&urlCount=5&token=" + url.QueryEscape(string(tok[1]))
	b, err := get(ctx, env.HTTP, u)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Targets []struct {
			URL      string `json:"url"`
			Location struct {
				City    string `json:"city"`
				Country string `json:"country"`
			} `json:"location"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("api.fast.com: %w", err)
	}
	var out []Endpoint
	seen := map[netip.Addr]bool{}
	for _, t := range doc.Targets {
		pu, err := url.Parse(t.URL)
		if err != nil {
			continue
		}
		host := pu.Hostname()
		a, err := resolve(ctx, env, host)
		if err != nil || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, Endpoint{Label: host, Addr: a, Meta: map[string]any{
			"city": t.Location.City, "country": t.Location.Country,
			"isp_hosted": strings.Contains(host, "-isp."),
		}})
	}
	if len(out) == 0 {
		return nil, errors.New("api.fast.com: no usable targets")
	}
	return out, nil
}

// Steam: the SDR configuration lists Valve's relay points of presence with
// their locations; the nearest ones carry the game traffic.

type sdrConfig struct {
	Pops map[string]struct {
		Desc   string    `json:"desc"`
		Geo    []float64 `json:"geo"` // longitude, latitude
		Relays []struct {
			IPv4 string `json:"ipv4"`
		} `json:"relays"`
	} `json:"pops"`
}

func steamSDR(ctx context.Context, env Env) ([]Endpoint, error) {
	b, err := get(ctx, env.HTTP, "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=730")
	if err != nil {
		return nil, err
	}
	var cfg sdrConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("sdr config: %w", err)
	}
	type pop struct {
		code, desc string
		km         float64
		addr       netip.Addr
	}
	var pops []pop
	for code, p := range cfg.Pops {
		if len(p.Geo) != 2 || len(p.Relays) == 0 {
			continue
		}
		a, err := netip.ParseAddr(p.Relays[0].IPv4)
		if err != nil || !config.UsableAddr(a) {
			continue
		}
		pops = append(pops, pop{code: code, desc: p.Desc, km: distanceKm(env.Lat, env.Lon, p.Geo[1], p.Geo[0]), addr: a})
	}
	if len(pops) == 0 {
		return nil, errors.New("sdr config: no relays")
	}
	slices.SortFunc(pops, func(a, b pop) int {
		if c := cmp.Compare(a.km, b.km); c != 0 {
			return c
		}
		return strings.Compare(a.code, b.code)
	})
	var out []Endpoint
	for _, p := range pops {
		out = append(out, Endpoint{Label: p.code + " " + p.desc, Addr: p.addr, Meta: map[string]any{
			"pop": p.code, "km": math.Round(p.km),
		}})
	}
	return out, nil
}

// GameLift: every region has a UDP ping beacon that echoes datagrams.

func gameLift(ctx context.Context, env Env) ([]Endpoint, error) {
	var out []Endpoint
	var errs []error
	for _, r := range env.GameLiftRegions {
		host := "gamelift-ping." + r + ".api.aws"
		a, err := resolve(ctx, env, host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, Endpoint{Label: r, Addr: a, Meta: map[string]any{"region": r, "host": host}})
	}
	if len(out) == 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// Discord: latency.discord.media/rtc lists the voice regions closest to the
// client, nearest first, with the addresses of their RTC servers.

func discordVoice(ctx context.Context, env Env) ([]Endpoint, error) {
	b, err := get(ctx, env.HTTP, "https://latency.discord.media/rtc")
	if err != nil {
		return nil, err
	}
	var regions []struct {
		Region string   `json:"region"`
		IPs    []string `json:"ips"`
	}
	if err := json.Unmarshal(b, &regions); err != nil {
		return nil, fmt.Errorf("discord rtc: %w", err)
	}
	var out []Endpoint
	for _, r := range regions {
		for _, s := range r.IPs {
			if a, err := netip.ParseAddr(s); err == nil && config.UsableAddr(a) {
				out = append(out, Endpoint{Label: r.Region, Addr: a, Meta: map[string]any{"region": r.Region}})
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("discord rtc: no regions")
	}
	return out, nil
}

// STUN: the servers come from the catalog entry of the service.

func stunServers(ctx context.Context, env Env) ([]Endpoint, error) {
	var out []Endpoint
	var errs []error
	for _, s := range env.STUN {
		host, port, err := splitHostPort(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		a, err := resolve(ctx, env, host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, Endpoint{Label: s, Addr: a, Port: port, Meta: map[string]any{"host": host}})
	}
	if len(out) == 0 {
		if len(errs) == 0 {
			return nil, errors.New("no stun servers listed in the catalog")
		}
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func splitHostPort(s string) (string, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, Specs["stun"].Port, nil
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("stun server %q: bad port", s)
	}
	return s[:i], p, nil
}

func distanceKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371
	rad := math.Pi / 180
	dlat, dlon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}

// DefaultTimeout bounds one discoverer run.
const DefaultTimeout = 20 * time.Second
