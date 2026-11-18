#!/bin/bash
#
# run.command -- double-click this in Finder to launch NetworkRegulator.
#
# macOS runs a .command file in Terminal when you double-click it, so you don't
# have to type anything. (First time only: if macOS blocks it as being from an
# "unidentified developer", right-click the file -> Open, then click Open.)
#
# On the FIRST run this installs everything the app can use (Python libraries +
# the command-line network tools via Homebrew). Later runs skip whatever is
# already installed and just launch. Nothing here ever blocks the app from
# starting -- if something can't be installed, it says so and launches anyway.
#
cd "$(dirname "$0")"

info()  { printf "\033[1;36m%s\033[0m\n" "$*"; }   # cyan
warn()  { printf "\033[1;33m%s\033[0m\n" "$*"; }   # yellow
good()  { printf "\033[1;32m%s\033[0m\n" "$*"; }   # green

# --------------------------------------------------------------------------- #
# 1) Self-update (best effort; never blocks launch)
# --------------------------------------------------------------------------- #
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  info "Checking for updates…"
  git pull --ff-only 2>&1 || echo "(couldn't update — launching the current version)"
fi

PYBIN="$(command -v python3 || command -v python)"
if [ -z "$PYBIN" ]; then
  warn "Python 3 is required but was not found. Install it from https://www.python.org/downloads/ then double-click again."
  read -r -p "Press Return to close… " _ ; exit 1
fi

# --------------------------------------------------------------------------- #
# 2) Python libraries -- install any that are missing (pip --user)
# --------------------------------------------------------------------------- #
# pip name  ->  import name (how we test whether it's already there)
PY_PKGS=(
  "pyobjc-framework-CoreWLAN=CoreWLAN"        # real SSIDs on macOS
  "pyobjc-framework-CoreLocation=CoreLocation"
  "getmac=getmac"                             # MAC for an IP
  "mac-vendor-lookup=mac_vendor_lookup"       # full vendor names
  "zeroconf=zeroconf"                         # mDNS friendly names
  "scapy=scapy"                               # packet crafting / ARP
  "pywifi=pywifi"                             # Wi-Fi scan / connect
  "mitmproxy=mitmproxy"                       # HTTP(S) interception
)
need=()
for entry in "${PY_PKGS[@]}"; do
  pip_name="${entry%%=*}"; import_name="${entry##*=}"
  if ! "$PYBIN" -c "import ${import_name}" >/dev/null 2>&1; then
    need+=("$pip_name")
  fi
done
if [ ${#need[@]} -gt 0 ]; then
  info "Installing Python libraries (first run): ${need[*]}"
  "$PYBIN" -m pip install --user --quiet "${need[@]}" \
    && good "Python libraries ready." \
    || warn "Some Python libraries failed to install — the app still runs with whatever is available."
else
  good "Python libraries already present."
fi

# Download the IEEE vendor database once, so vendor names are complete even
# offline afterwards (quietly skipped if mac-vendor-lookup isn't installed).
"$PYBIN" -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()" >/dev/null 2>&1 \
  && good "Vendor database downloaded." || true

# --------------------------------------------------------------------------- #
# 3) Command-line network tools -- install any that are missing (Homebrew)
# --------------------------------------------------------------------------- #
# These are system binaries, not pip packages. On macOS they come from Homebrew.
BREW_TOOLS=( aircrack-ng bettercap nmap naabu rustscan )
if command -v brew >/dev/null 2>&1; then
  missing=()
  for t in "${BREW_TOOLS[@]}"; do command -v "$t" >/dev/null 2>&1 || missing+=("$t"); done
  if [ ${#missing[@]} -gt 0 ]; then
    info "Installing network tools with Homebrew (first run — this can take several minutes): ${missing[*]}"
    for t in "${missing[@]}"; do
      info "  → brew install $t"
      brew install "$t" >/dev/null 2>&1 && good "    installed $t" \
        || warn "    couldn't install $t (run 'brew install $t' yourself to retry)"
    done
  else
    good "Network tools already installed."
  fi
else
  warn "Homebrew isn't installed, so the command-line tools (aircrack-ng, bettercap, nmap, naabu, rustscan) can't be auto-installed."
  warn "Install Homebrew once with this line, then double-click run.command again:"
  warn '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
  warn "The app still launches now with the features that don't need those tools."
fi

# --------------------------------------------------------------------------- #
# 4) Honest hardware note
# --------------------------------------------------------------------------- #
warn "Heads-up: disconnecting devices over Wi-Fi (deauth) also needs a monitor-mode USB adapter — the built-in Mac card physically can't inject packets. Scanning, the device list, vendor names, and routing traffic through this Mac (bettercap) all work without one."

good "Launching NetworkRegulator…"
exec "$PYBIN" network_scanner.py
