package procwatch

import (
	"testing"
	"testing/fstest"
)

func TestObserveCgroupV1(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/2808/comm":    {Data: []byte("dnscrypt-proxy\n")},
		"proc/2808/cmdline": {Data: []byte("/opt/anondns/bin/dnscrypt-proxy\x00")},
		"proc/2808/status":  {Data: []byte("Name:\tdnscrypt-proxy\nVmRSS:\t   21400 kB\n")},
		"proc/2808/cgroup":  {Data: []byte("4:cpu,cpuacct:/lxc/anondns\n3:memory:/lxc/anondns\n1:name=systemd:/\n")},
		"sys/fs/cgroup/memory/lxc/anondns/memory.usage_in_bytes":     {Data: []byte("31457280\n")},
		"sys/fs/cgroup/memory/lxc/anondns/memory.limit_in_bytes":     {Data: []byte("62914560\n")},
		"sys/fs/cgroup/memory/lxc/anondns/memory.max_usage_in_bytes": {Data: []byte("40000000\n")},
		"sys/fs/cgroup/memory/lxc/anondns/memory.failcnt":            {Data: []byte("3\n")},
	}
	st, err := Observe(fsys, "dnscrypt-proxy")
	if err != nil {
		t.Fatal(err)
	}
	want := Status{Name: "dnscrypt-proxy", PID: 2808, RSSkB: 21400, Cgroup: "/lxc/anondns",
		MemUsage: 31457280, MemLimit: 62914560, MemPeak: 40000000, OOMEvents: 3, HasMem: true}
	if st != want {
		t.Fatalf("got %+v\nwant %+v", st, want)
	}
}

func TestObserveCgroupV2AndRoot(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/10/comm":    {Data: []byte("dnsmasq\n")},
		"proc/10/cmdline": {Data: []byte("dnsmasq\x00")},
		"proc/10/status":  {Data: []byte("VmRSS:\t 2560 kB\n")},
		"proc/10/cgroup":  {Data: []byte("0::/system.slice/dnsmasq.service\n")},
		"sys/fs/cgroup/system.slice/dnsmasq.service/memory.current": {Data: []byte("1048576\n")},
		"sys/fs/cgroup/system.slice/dnsmasq.service/memory.max":     {Data: []byte("max\n")},
		"sys/fs/cgroup/system.slice/dnsmasq.service/memory.events":  {Data: []byte("low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\n")},
		"proc/11/comm":    {Data: []byte("other\n")},
		"proc/11/cmdline": {Data: []byte("other\x00")},
		"proc/11/cgroup":  {Data: []byte("3:memory:/\n")},
	}
	st, err := Observe(fsys, "dnsmasq")
	if err != nil || !st.HasMem || st.MemUsage != 1048576 || st.MemLimit != 0 || st.OOMEvents != 1 || st.RSSkB != 2560 {
		t.Fatalf("%+v %v", st, err)
	}
	st, _ = Observe(fsys, "other")
	if st.HasMem || st.Cgroup != "" {
		t.Fatalf("root cgroup reported: %+v", st)
	}
	st, err = Observe(fsys, "absent")
	if err != nil || st.PID != 0 {
		t.Fatalf("%+v %v", st, err)
	}
}
