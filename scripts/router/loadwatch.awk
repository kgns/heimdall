# Live view: one line per WAN sample with throughput and the latest ICMP
# RTT of the watched targets, to see latency react to load.
# usage: tail -f /var/tmp/heimdall/samples.jsonl | awk -v watch='isp-hop1 youtube/www.youtube.com' -f loadwatch.awk
BEGIN {
    n = split(watch, w, " ")
    printf "%-8s %9s %9s", "time", "rx Mbit", "tx Mbit"
    for (i = 1; i <= n; i++) printf " %14.14s", w[i]
    printf "\n"
}
function num(name,    v) {
    if (!match($0, "\"" name "\":-?[0-9.e+]+")) return ""
    v = substr($0, RSTART, RLENGTH)
    sub(/^"[^"]*":/, "", v)
    return v + 0
}
/"kind":"icmp"/ {
    for (i = 1; i <= n; i++)
        if (index($0, "\"target_id\":\"" w[i] "\"")) {
            v = num("rtt_ms")
            last[i] = (v == "") ? "lost" : sprintf("%.1f", v)
        }
}
/"kind":"wan"/ {
    printf "%-8s %9.2f %9.2f", strftime("%H:%M:%S", int(num("ts_ms") / 1000)), num("rx_bps") / 1e6, num("tx_bps") / 1e6
    for (i = 1; i <= n; i++) printf " %14s", (i in last) ? last[i] : "-"
    printf "\n"
    fflush()
}
