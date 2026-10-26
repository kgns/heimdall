# Mean HTTP phase times per target for successful requests. With TLS 1.3 the
# handshake costs one round trip, so tls_ms far above connect_ms points at
# client-side CPU time.
# usage: awk -f httpphases.awk /var/tmp/heimdall/samples.jsonl* | sort
function field(name,    v) {
    if (!match($0, "\"" name "\":[0-9.]+")) return -1
    v = substr($0, RSTART, RLENGTH)
    sub(/^"[^"]*":/, "", v)
    return v + 0
}
/"kind":"http"/ && /"status":"ok"/ {
    if (!match($0, /"target_id":"[^"]+"/)) next
    t = substr($0, RSTART + 13, RLENGTH - 14)
    n[t]++
    c = field("connect_ms"); if (c >= 0) { cs[t] += c; cn[t]++ }
    l = field("tls_ms");     if (l >= 0) { ls[t] += l; ln[t]++ }
    f = field("ttfb_ms");    if (f >= 0) { fs[t] += f; fn[t]++ }
}
END {
    for (t in n)
        printf "%-52s n %3d connect %7.1f tls %7.1f ttfb %7.1f\n", t, n[t],
            cn[t] ? cs[t] / cn[t] : 0, ln[t] ? ls[t] / ln[t] : 0, fn[t] ? fs[t] / fn[t] : 0
}
