# Heimdall: 3-minute talk

Slides: `slides.html` (open in a browser, or `heimdall.pdf`; `slide-1.png`
and `slide-2.png` for Google Slides). `scripts/demo` and
`scripts/status-link` are in the repository root.

## Before the meeting

- `scripts/demo on 30`: fast detection for 30 minutes, notifier warmed up.
- `scripts/demo traffic 15` a few minutes before the demo: connections at
  normal speed, so the probes have this laptop's usual latency as the
  baseline the slowdown is compared with.
- Tabs: Slack, https://heimdall.kgns.dev (topology), the slides.
- Rehearse once a few minutes before, so Grafana already shows an incident
  (Firehose delivers samples to Athena every 5 minutes).

## Slide 1 (about 1:30)

When a customer says "the internet is slow", nobody knows whether it is the
Wi-Fi, the extender, the ISP's line, the ISP's route to a service, or the
service itself, so support calls go in circles.

Heimdall puts a small probe on the home gateway and on the mesh extender. It
sees every connection the home's devices make, splits each round trip into
the Wi-Fi part and the internet part, and pings the ISP's first hops and 37
services. A reference probe in AWS measures the same services from the
cloud, which tells the ISP's route from the service itself. The row on top
is a real day at home: about 2 ms of Wi-Fi, 2 ms through the extender, 4 ms
on the ISP's line, the rest is the internet.

A slowdown becomes an incident with a likely cause: a Slack alert, and a
status page for the ISP and for the customer that says who should act and
what to do.

## Slide 2: the demo (about 1:30)

1. `scripts/demo slow 40`: "I'm adding 40 ms to my own laptop, which is on
   the extender's Wi-Fi."
2. Slack: the alert arrives in about 10 seconds. kagan-pc, its hop to the
   extender 41 ms against 1 ms usually.
3. Open the status page link in the post: the customer's home network, not
   the ISP; the line, the route and the services were normal at the same
   time; here is the fix. Switch to "For the customer", then the link to the
   home's weekly report.
4. `scripts/demo fix`: the page turns to Resolved by itself and Slack posts
   the end about 20 seconds later.

After the meeting: `scripts/demo off`.
