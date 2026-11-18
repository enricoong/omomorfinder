#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# OmomorFinder installer for Kali Linux (and any Debian-based distro).
#
# Kali marks the system Python as "externally managed" (PEP 668), so the tool
# is installed in a private virtual environment (.venv) next to this script,
# and a launcher is placed in ~/.local/bin/omomorfinder.
#
# Usage:
#   ./install.sh           core install (standard + fast profiles)
#   ./install.sh --deep    also OpenCV, Playwright/Chromium, sentence-transformers
# -----------------------------------------------------------------------------
set -euo pipefail

C1=$'\e[38;5;51m'; C2=$'\e[38;5;141m'; OK=$'\e[38;5;43m'; WARN=$'\e[38;5;220m'; ERR=$'\e[38;5;197m'; R=$'\e[0m'
step() { printf '%s›%s %s\n' "$C2" "$R" "$*"; }
ok()   { printf '  %s●%s %s\n' "$OK" "$R" "$*"; }
warn() { printf '  %s▲%s %s\n' "$WARN" "$R" "$*"; }
die()  { printf '  %s✗%s %s\n' "$ERR" "$R" "$*"; exit 1; }

DEEP=0
for arg in "$@"; do
  case "$arg" in
    --deep) DEEP=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown option: $arg" ;;
  esac
done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
printf '\n%sOmomorFinder%s installer\n\n' "$C1" "$R"

SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

step "checking Python"
command -v python3 >/dev/null 2>&1 || die "python3 not found (apt install python3)"
python3 - <<'EOF' || die "Python >= 3.11 required"
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
EOF
ok "$(python3 --version)"

step "checking venv support"
if ! python3 -c "import ensurepip, venv" >/dev/null 2>&1; then
  warn "installing python3-venv"
  $SUDO apt-get update -qq && $SUDO apt-get install -y -qq python3-venv
fi
ok "venv available"

step "creating virtual environment (.venv)"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip wheel setuptools
ok "ready"

step "installing core dependencies"
.venv/bin/python -m pip install -q -e .
ok "httpx, dnspython, rich, bs4/lxml, pillow, numpy, mmh3, idna"

if [ "$DEEP" -eq 1 ]; then
  step "installing deep-mode dependencies (this can take a while)"
  .venv/bin/python -m pip install -q torch --index-url https://download.pytorch.org/whl/cpu \
    || warn "CPU torch wheel failed, sentence-transformers will pull the default one"
  .venv/bin/python -m pip install -q -e ".[deep]"
  ok "opencv, playwright, sentence-transformers"
  step "installing headless Chromium"
  if ! .venv/bin/python -m playwright install --with-deps chromium; then
    warn "--with-deps failed (no sudo?), trying browser only"
    .venv/bin/python -m playwright install chromium || warn "Chromium not installed: screenshots disabled"
  fi
fi

step "creating launcher"
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/omomorfinder" <<EOF
#!/usr/bin/env bash
exec "$DIR/.venv/bin/python" -m omomorfinder "\$@"
EOF
chmod +x "$HOME/.local/bin/omomorfinder"
ok "$HOME/.local/bin/omomorfinder"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) warn "add ~/.local/bin to PATH:  echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.zshrc" ;;
esac

step "downloading datasets and models"
"$HOME/.local/bin/omomorfinder" --setup || warn "setup incomplete: datasets will be fetched on first run"

mkdir -p "$HOME/.config/omomorfinder"
if [ ! -f "$HOME/.config/omomorfinder/.env" ]; then
  cp .env.example "$HOME/.config/omomorfinder/.env"
  chmod 600 "$HOME/.config/omomorfinder/.env"
  ok "API key template: ~/.config/omomorfinder/.env"
fi

printf '\n%sdone.%s  try:  %somomorfinder example.com%s\n\n' "$OK" "$R" "$C1" "$R"
