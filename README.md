# pico_exporter

### A tiny Linux system metrics exporter for OTLP
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Language](https://img.shields.io/badge/language-C11-orange.svg)]() [![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://github.com/dpaneda/pico_exporter) [![Targets](https://img.shields.io/badge/targets-x86_64%20%7C%20aarch64-brightgreen.svg)]()

A ~100 KiB static binary that collects system metrics and pushes them directly to an OTLP endpoint, using only ~30 KiB of RAM at idle.

**Drop-in compatible with Prometheus node_exporter**. It exposes the same system metrics, so existing dashboards can be reused.

Written in C, with x86_64 and aarch64 support, TLS, and no runtime dependencies.

## Why?

I wanted to collect system metrics from a Raspberry Pi and send them to an OTLP endpoint.

The existing solutions worked, but running hundreds of megabytes of telemetry infrastructure just to collect a handful of system metrics felt excessive. So I decided to build a small exporter while keeping compatibility with `node_exporter` metrics.

What I did not expect was to win three orders of magnitude of memory doing it.

[Read the full story →](JOURNEY.md)

## ✨ Features

- **Push-only**: pushes to an HTTPS endpoint, uncompressed.
- **TLS via BearSSL**: one cipher suite, one curve, trust anchor compiled in.
- **No `malloc` on the hot cycle path.**
- **Static binaries, no shared libraries**: both x86_64 and aarch64 targets
  are production-ready.


## 📊 Resource usage

Only Grafana Alloy is compared here, because it is the one that does
everything and can be measured head-to-head with pico_exporter. Measured on
my machine, over the same running window:

| | Grafana Alloy | pico_exporter | Ratio |
|---|---|---|---|
| Binary size | 530 000 kB | 100 kB | **5300× smaller** |
| Resting RSS | 400 000 kB | 30 kB | **~13 000× less memory** |
| CPU per day | 516 s | 6 s | **86× less CPU** |
| Collection time | 50 ms | 6 ms | **8× faster** |

## ⚖️ Alternatives

Compared with [Grafana Alloy](https://github.com/grafana/alloy) and the Prometheus *node_exporter*:

| | pico_exporter | Grafana Alloy | node_exporter |
|---|---|---|---|
| Delivery | push (OTLP) | push (OTLP) and pull | pull |
| Metrics scope | core system metrics + textfile | Full OpenTelemetry ecosystem | System metrics (extensible) |
| Logs & traces | no | yes | no |
| Configuration | a few environment variables | Declarative config file | Many flags |
| Extensibility | Fixed set | Large component catalog | Collector plugins |
| Language | C11 | Go | Go |
| Binary | ~100 KiB | ~530 MB | ~22 MB |


## 🚀 Getting started

1.  Download the binary for your architecture from the latest
    [release](https://github.com/dpaneda/pico_exporter/releases):

```sh
curl -fsSL -o pico_exporter \
  https://github.com/dpaneda/pico_exporter/releases/latest/download/pico_exporter-aarch64
chmod +x pico_exporter
```

2.  Point it at a gateway and run:

```sh
GW_URL=https://your-otlp-gateway/otlp/v1/metrics \
GW_USER=your-user GW_PASS=your-password \
./pico_exporter
```

For building from source and the host prerequisites, see
[DEVELOPMENT.md](DEVELOPMENT.md).

## ⚙️ Configuration

Configuration is environment-based:

| Env | Required | Default | Meaning |
|---|---|---|---|
| `GW_URL` | yes | none | Push endpoint, `https://host[:port]/path` or `http://…` |
| `GW_USER` / `GW_PASS` | no | empty | HTTP Basic Auth credentials (Grafana Cloud: stack ID / `glc_…`) |
| `JOB` | no | `integrations/node_exporter` | OTel `service.name` → Prometheus `job` |
| `INSTANCE` | no | `uname -n` | OTel `service.instance.id` → Prometheus `instance`. Set it when two exporters share a host so they do not collide into one series |
| `INTERVAL` | no | `15` | Collection/push cycle in seconds |
| `BATCH` | no | `100` | Samples per OTLP request |
| `TEXTFILE_DIR` | no | unset | Directory of `*.prom` files to fold into each push; unset disables the collector |

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
