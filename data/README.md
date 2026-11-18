# data/

**`oui_vendors.tsv.gz`** — a gzipped `OUI-prefix<TAB>vendor` table used to turn a
device's MAC address into a manufacturer name (e.g. `7c:d1:ad` → `Apple`).

Each line is a 24-bit MAC prefix (6 hex chars, uppercase) and the registered
organization. The underlying assignments are facts from the public **IEEE OUI
registry**; this compact copy was derived from nmap's `nmap-mac-prefixes`.
~39k prefixes, ~340 KB.

To refresh it:

```bash
curl -fsSL https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes -o /tmp/nmap-mac
grep -vE '^#' /tmp/nmap-mac \
  | awk 'NF>=2 && $1 ~ /^[0-9A-Fa-f]{6}$/ { pfx=toupper($1); $1=""; sub(/^ /,""); print pfx"\t"$0 }' \
  | sort -u | gzip -9 -c > data/oui_vendors.tsv.gz
```
