# pico_exporter

### Minimal footprint OTLP system metrics exporter in C

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Language](https://img.shields.io/badge/language-C11-orange.svg)]() [![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://github.com/dpaneda/pico_exporter) [![Targets](https://img.shields.io/badge/targets-x86_64%20%7C%20aarch64-brightgreen.svg)]()

pico_exporter is a **system metrics exporter written in C that idles in
28 kiB of memory on a Raspberry Pi** (`smaps_rollup` between push cycles;
20-32 kiB on x86). It is a drop-in replacement for the Prometheus
*node_exporter*, but instead of waiting to be scraped it **pushes** the metrics
to an OTLP gateway over TLS, so there is no need for an extra piece of software
to pick the metrics up and forward them to the gateway.

I wanted system metrics from a Raspberry Pi, and every alternative I came
across seemed to use an absurd amount of resources for the work it had to do.
So I built my own. What I did not expect was to win three orders of
magnitude of memory doing it. For the full story, see [JOURNEY.md](JOURNEY.md).

## ✨ Features

- **Push-only**: pushes to an HTTPS endpoint, uncompressed.
- **TLS via BearSSL**: one cipher suite, one curve, trust anchor compiled in.
- **No `malloc` on the hot cycle path.**
- **Static binaries, no shared libraries**: both x86_64 and aarch64 targets
  are production-ready.

## ⚖️ Comparison

Compared with the usual alternatives, [Grafana Alloy](https://github.com/grafana/alloy) and the Prometheus *node_exporter*:

### Features

| | Grafana Alloy | node_exporter | pico_exporter |
|---|---|---|---|
| Delivery | push (OTLP) and pull | pull based | push only |
| Metrics scope | Full OpenTelemetry ecosystem | system metrics (extensible) | core system metrics + textfile |
| Logs & traces | yes | no | no |
| Configuration | declarative config file | many flags | a few env vars |
| Extensibility | large component catalog | collector plugins | fixed set |
| Language | Go | Go | C11 |
| Binary | ~530 MB | ~22 MB | ~100 kB |

### Resources

Only Grafana Alloy is compared here, because it is the one that does
everything and can be measured head-to-head with pico_exporter. Measured on
my machine, over the same running window:

| | Grafana Alloy | pico_exporter | Ratio |
|---|---|---|---|
| Binary size | 530 000 kB | 100 kB | **5300× smaller** |
| Resting RSS | 400 000 kB | 30 kB¹ | **~13 000× less memory**¹ |
| CPU per day | 516 s | 6 s | **86× less CPU** |
| Scrape time | 50 ms | 6 ms | **8× faster** |

¹ pico_exporter's figure is `smaps_rollup` between push cycles on the Pi (28 kB measured 2026-09-25, see AGENTS.md), rounded. The ratio is derived from that figure.

## 👨‍💻 Getting started

1.  Download the binary for your architecture from the latest
    [release](https://github.com/dpaneda/pico_exporter/releases):

```sh
curl -fsSL -o pico_exporter \
  https://github.com/dpaneda/pico_exporter/releases/latest/download/pico_exporter-aarch64
chmod +x pico_exporter
```

2.  Point it at a gateway and run:

```sh
GW_URL=https://otlp-gateway-prod/otlp/v1/metrics \
GW_USER=12345 GW_PASS=glc_... \
./pico_exporter
```

For building from source and the host prerequisites, see
[DEVELOPMENT.md](DEVELOPMENT.md).

## ⚙️ Configuration

Configuration is environment-based:

| Env | Required | Default | Meaning |
|---|---|---|---|
| `GW_URL` | yes (push mode) | none | push endpoint, `https://host[:port]/path` or `http://…` |
| `GW_USER` / `GW_PASS` | no | empty | HTTP Basic-auth (Grafana Cloud: stack id / `glc_…`) |
| `JOB` | no | `integrations/node_exporter` | OTel `service.name` → Prometheus `job` |
| `INSTANCE` | no | `uname -n` | OTel `service.instance.id` → Prometheus `instance`. Set it when two exporters share a host so they do not collide into one series |
| `INTERVAL` | no | `15` | collection/push cycle in seconds |
| `BATCH` | no | `100` | samples per OTLP request |
| `TEXTFILE_DIR` | no | unset | directory of `*.prom` files to fold into each push; unset disables the collector |

## 📦 Deploy

Drop the binary on the host, point it at your gateway and run it under
whatever supervises your services. There is a ready unit in
[`contrib/pico_exporter.service`](contrib/pico_exporter.service).

Every push writes a line to the log, so the journal is the whole health
check: if it is working, you will see it say so each cycle.

### The trust anchor is compiled in

There is no CA bundle on disk to point at: the root certificate is baked into
the binary, and the default is **DigiCert G2**, the CA behind Grafana Cloud's
gateway. Any endpoint signed by something else fails validation, and the fix is
a rebuild rather than a flag. Point the build at the endpoint and it captures
and compiles in the chain that endpoint serves:

```sh
make GW_URL=https://your-gateway:443/
```

`INSECURE=1` skips validation altogether. It is not recommended: the binary
then trusts any well-formed certificate, so anyone on the path can read and
rewrite what you push.
