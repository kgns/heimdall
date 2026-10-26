# ICMP tail behaviour per target: min, max and how many answers were more
# than 10 ms above the minimum. Pass target ID fragments to keep with
# -v only='isp-hop1|teams|youtube'.
# usage: awk -v only='...' -f icmptails.awk /var/tmp/heimdall/samples.jsonl* | sort
/"kind":"icmp"/ && /"status":"ok"/ {
    if (!match($0, /"target_id":"[^"]+"/)) next
    t = substr($0, RSTART + 13, RLENGTH - 14)
    if (only != "" && t !~ only) next
    if (!match($0, /"rtt_ms":[0-9.]+/)) next
    v = substr($0, RSTART + 9, RLENGTH - 9) + 0
    n[t]++
    r[t, n[t]] = v
    if (!(t in mn) || v < mn[t]) mn[t] = v
    if (v > mx[t]) mx[t] = v
}
END {
    for (t in n) {
        sp = 0
        for (i = 1; i <= n[t]; i++) if (r[t, i] > mn[t] + 10) sp++
        printf "%-34s n %5d min %6.2f max %7.2f spikes>min+10 %4d\n", t, n[t], mn[t], mx[t], sp
    }
}
