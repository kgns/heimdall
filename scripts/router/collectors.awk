# Summary of the context collectors: WAN throughput, CPU, LAN clients,
# DNS-path daemons and clock offset.
# usage: awk -f collectors.awk /var/tmp/heimdall/samples.jsonl*
function num(name,    v) {
    if (!match($0, "\"" name "\":-?[0-9.e+]+")) return ""
    v = substr($0, RSTART, RLENGTH)
    sub(/^"[^"]*":/, "", v)
    return v + 0
}
function str(name,    v) {
    if (!match($0, "\"" name "\":\"[^\"]*\"")) return ""
    v = substr($0, RSTART, RLENGTH)
    sub(/^"[^"]*":"/, "", v)
    sub(/"$/, "", v)
    return v
}
/"kind":"wan"/ {
    rx = num("rx_bps") / 1e6; tx = num("tx_bps") / 1e6
    wn++; wrx += rx; wtx += tx
    if (rx > wrxm) wrxm = rx
    if (tx > wtxm) wtxm = tx
    wdrop += num("rx_drop") + num("tx_drop")
    wif = str("target_id")
}
/"kind":"cpu"/ {
    b = num("busy_pct"); cn++; cb += b
    if (b > cbm) cbm = b
    s = num("softirq_pct"); if (s > csm) csm = s
    noports += num("udp_noports"); retrans += num("tcp_retrans"); rcvbuf += num("udp_rcvbuf_errors")
}
/"kind":"lan"/ {
    id = str("target_id"); ln[id]++
    lmed[id] = str("medium") "/" str("port"); lip[id] = str("dst_ip")
    v = num("rtt_ms")
    if (v != "") { lok[id]++; ls[id] += v; if (v > lmx[id]) lmx[id] = v }
}
/"kind":"dnshealth"/ { dh[str("target_id")] = $0 }
/"kind":"clock"/ && /"status":"ok"/ { kn++; kd += num("rtt_ms"); koff = num("offset_ms"); kref = str("dst_ip") }
/"event":"(lan_client_[a-z]+|process_[a-z]+|wan_change)"/ { ev[str("event")]++ }
END {
    if (wn) printf "wan %s: %d samples, rx avg %.2f max %.2f Mbit/s, tx avg %.2f max %.2f Mbit/s, drops %d\n", wif, wn, wrx / wn, wrxm, wtx / wn, wtxm, wdrop
    if (cn) printf "cpu: %d samples, busy avg %.1f%% max %.1f%%, softirq max %.1f%%, udp_noports %d, udp_rcvbuf_errors %d, tcp_retrans %d\n", cn, cb / cn, cbm, csm, noports, rcvbuf, retrans
    for (id in ln) printf "lan %s %-15s %-14s n %4d ok %4d avg %7.2f max %7.2f\n", id, lip[id], lmed[id], ln[id], lok[id], lok[id] ? ls[id] / lok[id] : 0, lmx[id]
    for (p in dh) {
        $0 = dh[p]
        printf "%s: pid %s rss %s kB", p, num("pid"), num("rss_kb")
        if (num("mem_usage") != "") printf ", cgroup %s %.1f/%.1f MiB, peak %.1f MiB, oom %s", str("cgroup"), num("mem_usage") / 1048576, num("mem_limit") / 1048576, num("mem_peak") / 1048576, num("oom_events")
        if (str("reason") != "") printf " (%s)", str("reason")
        printf "\n"
    }
    if (kn) printf "clock: %d checks via %s, last offset %.1f ms, avg delay %.1f ms\n", kn, kref, koff, kd / kn
    for (e in ev) printf "event %s: %d\n", e, ev[e]
}
