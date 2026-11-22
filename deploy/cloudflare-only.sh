#!/bin/sh
# Lets only Cloudflare reach TCP port $1 (default 443): everyone else gets no
# answer at all, so scanning the server's IP finds nothing to tie it to the
# domain. Re-run it now and then; Cloudflare's ranges change rarely.
set -eu
PORT="${1:-443}"
CHAIN=SALLYPORT_CF

fetch() { curl -fsS --max-time 15 "https://www.cloudflare.com/$1"; }
V4=$(fetch ips-v4)
V6=$(fetch ips-v6)
[ -n "$V4" ] || { echo "could not fetch Cloudflare ranges" >&2; exit 1; }

apply() { # $1 = iptables or ip6tables, $2 = ranges
	"$1" -N "$CHAIN" 2>/dev/null || "$1" -F "$CHAIN"
	for r in $2; do
		"$1" -A "$CHAIN" -s "$r" -j RETURN
	done
	"$1" -A "$CHAIN" -j DROP
	"$1" -C INPUT -p tcp --dport "$PORT" -j "$CHAIN" 2>/dev/null ||
		"$1" -I INPUT -p tcp --dport "$PORT" -j "$CHAIN"
}
apply iptables "$V4"
command -v ip6tables >/dev/null && apply ip6tables "$V6"
echo "TCP $PORT now accepts Cloudflare only ($(echo "$V4" | wc -l) IPv4 ranges)"
