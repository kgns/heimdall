# Per target and kind: sample count, answered count and mean RTT.
# usage: awk -f summary.awk /var/tmp/heimdall/samples.jsonl*
{
    if (!match($0, /"kind":"[a-z_]+"/)) next
    k = substr($0, RSTART + 8, RLENGTH - 9)
    if (k != "icmp" && k != "tcp" && k != "http" && k != "dns") next
    if (!match($0, /"target_id":"[^"]+"/)) next
    key = substr($0, RSTART + 13, RLENGTH - 14) " " k
    n[key]++
    if (match($0, /"rtt_ms":[0-9.]+/)) {
        ok[key]++
        s[key] += substr($0, RSTART + 9, RLENGTH - 9)
    }
}
END {
    for (x in n)
        printf "%-62s n %5d ok %5d avg %8.2f\n", x, n[x], ok[x], ok[x] ? s[x] / ok[x] : 0
}
