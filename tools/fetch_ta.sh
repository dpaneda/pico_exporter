#!/usr/bin/env bash
# tools/fetch_ta.sh <https_URL> <out.pem>
# Trust-on-first-use CA discovery for make GW_URL=...: connects to the
# endpoint, captures every PEM cert the server presents during the TLS
# handshake (leaf + intermediates + root when sent) and writes them to
# <out.pem> as a CAFILE bundle. Then the normal gen_ta.sh path turns that
# bundle into the compiled-in trust anchors.
#
# TOFU: whatever the endpoint serves at fetch time becomes the trust anchor
# set. That pins the certificate chain (strictly stronger than INSECURE=1,
# strictly weaker than installing the real root by hand), and it is NOT
# refreshed at runtime - the binary is rebuilt with the fresh chain when the
# endpoint rotates its CA. The fetch is cached: it only re-runs when the
# bundle is missing (or with CA_REFRESH=1, or after deleting the bundle).
set -euo pipefail

url="${1:?usage: fetch_ta.sh <URL> <out.pem>}"
outfile="${2:?usage: fetch_ta.sh <URL> <out.pem>}"

if [ -f "$outfile" ] && [ "${CA_REFRESH:-0}" != 1 ]; then
    echo "fetch_ta: using cached $outfile (CA_REFRESH=1 or delete it to refetch)" >&2
    exit 0
fi

command -v openssl >/dev/null 2>&1 || {
    echo "fetch_ta: openssl is required to fetch the chain from a URL" >&2
    exit 1
}

proto="${url%%:*}"
rest="${url#*://}"
rest="${rest%%/*}"
case "$proto" in
    https|http) ;;
    *) echo "fetch_ta: unsupported protocol '$proto' in $url (use https://...)" >&2; exit 1 ;;
esac
host="${rest%%:*}"
if [[ "$rest" == *:* ]]; then
    port="${rest##*:}"
else
    port=443
    [ "$proto" = http ] && port=80
fi
echo "fetch_ta: connecting to $host:$port (SNI $host)" >&2

pems="$(openssl s_client -connect "$host:$port" -servername "$host" -showcerts \
    </dev/null 2>/dev/null \
    | awk '/-----BEGIN CERTIFICATE-----/{f=1} f{print} /-----END CERTIFICATE-----/{f=0}')"

ncerts=$(printf '%s\n' "$pems" | grep -c -- '-----BEGIN CERTIFICATE-----' || true)
if [ "$ncerts" -lt 1 ]; then
    echo "fetch_ta: no certificates in the handshake from $url (connect failed?)" >&2
    exit 1
fi

mkdir -p "$(dirname "$outfile")"
printf '%s\n' "$pems" > "$outfile"

echo "fetch_ta: captured $ncerts certificate(s):" >&2
i=0
printf '%s\n' "$pems" | awk '/-----BEGIN CERTIFICATE-----/{f=1; b=""; n++} f{b=b $0 "\n"} /-----END CERTIFICATE-----/{f=0; cmd="openssl x509 -noout -subject -fingerprint -sha256 2>/dev/null"; print b | cmd; close(cmd)}' >&2 || true
echo "fetch_ta: wrote $outfile" >&2