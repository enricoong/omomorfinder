#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# OmomorFinder installer for Kali Linux (and other Debian-based distros).
#
# Kali marks the system Python as "externally managed" (PEP 668), so the tool
# lives in a private virtual environment (.venv) next to this script and a
# small launcher is created in ~/.local/bin/omomorfinder.
#
# Every important step (apt packages, downloads, files outside this folder)
# is confirmed first, and every command is printed before it runs.
#
# Usage:
#   ./install.sh               interactive install
#   ./install.sh --deep        also install the deep-mode components
#   ./install.sh --no-deep     never ask about deep mode
#   ./install.sh -y            accept every default (non-interactive)
#   ./install.sh --uninstall   remove launcher, .venv, cache and datasets
# -----------------------------------------------------------------------------
set -Eeuo pipefail

# ---- presentation -------------------------------------------------------------
if [ -t 1 ]; then
  C1=$'\e[38;5;51m'; C2=$'\e[38;5;141m'; OK=$'\e[38;5;43m'; WARN=$'\e[38;5;220m'
  ERR=$'\e[38;5;197m'; DIM=$'\e[38;5;245m'; B=$'\e[1m'; R=$'\e[0m'
else
  C1=""; C2=""; OK=""; WARN=""; ERR=""; DIM=""; B=""; R=""
fi
step() { printf '\n%s›%s %s%s%s\n' "$C2" "$R" "$B" "$*" "$R"; }
ok()   { printf '  %s●%s %s\n' "$OK" "$R" "$*"; }
info() { printf '  %s•%s %s\n' "$C1" "$R" "$*"; }
warn() { printf '  %s▲%s %s\n' "$WARN" "$R" "$*"; }
die()  { printf '  %s✗%s %s\n' "$ERR" "$R" "$*" >&2; exit 1; }
trap 'die "unexpected error at line $LINENO (command: $BASH_COMMAND)"' ERR

# Print a command, then run it (the same "show what runs" idea as the tool).
run() {
  printf '    %s$ %s%s\n' "$DIM" "$*" "$R"
  "$@"
}

# True when a controlling terminal can be read (false in pipes, CI, cron...).
has_tty() { { : </dev/tty; } 2>/dev/null; }

# ask "question" Y|N  -> returns 0 for yes. Honors -y; without a terminal
# the default answer is used and printed, so logs show what was decided.
ask() {
  local question="$1" default="${2:-Y}" answer hint
  if [ "$default" = "Y" ]; then hint="[Y/n]"; else hint="[y/N]"; fi
  printf '  %s?%s %s %s%s%s ' "$C2" "$R" "$question" "$DIM" "$hint" "$R"
  if [ "$ASSUME_YES" -eq 1 ]; then
    printf '%syes (-y)%s\n' "$DIM" "$R"; return 0
  fi
  if ! has_tty; then
    if [ "$default" = "Y" ]; then answer="yes"; else answer="no"; fi
    printf '%s%s (default, no terminal)%s\n' "$DIM" "$answer" "$R"
    [ "$default" = "Y" ]; return
  fi
  read -r answer </dev/tty || answer=""
  answer="${answer:-$default}"
  case "$answer" in [yYsS]*) return 0 ;; *) return 1 ;; esac
}

# pip wrapper: hides setuptools' harmless "editable installation" banner.
pip_install() {
  printf '    %s$ %s -m pip install %s%s\n' "$DIM" "$VPY" "$*" "$R"
  "$VPY" -m pip install --disable-pip-version-check "$@" 2>&1 | sed '/BuildBackendWarning/,/wheel_obj/d'
}

# ---- options ---------------------------------------------------------------------
DEEP=""          # "", "yes" or "no"
ASSUME_YES=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --deep) DEEP="yes" ;;
    --no-deep) DEEP="no" ;;
    -y|--yes) ASSUME_YES=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $arg (see --help)" ;;
  esac
done

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
VENV="$DIR/.venv"
VPY="$VENV/bin/python"
LAUNCHER="$HOME/.local/bin/omomorfinder"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
fi

printf '\n%s%sOmomorFinder%s installer  %s(%s)%s\n' "$B" "$C1" "$R" "$DIM" "$DIR" "$R"

# ---- uninstall ---------------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  step "Uninstall"
  if [ -e "$LAUNCHER" ] && ask "Remove the launcher $LAUNCHER?" Y; then run rm -f "$LAUNCHER"; fi
  if [ -d "$VENV" ] && ask "Remove the virtual environment $VENV?" Y; then run rm -rf "$VENV"; fi
  if ask "Remove cache and datasets (~/.cache/omomorfinder, ~/.local/share/omomorfinder)?" Y; then
    run rm -rf "$HOME/.cache/omomorfinder" "$HOME/.local/share/omomorfinder"
  fi
  info "API keys in ~/.config/omomorfinder/.env were kept (delete them manually if needed)"
  ok "uninstalled"
  exit 0
fi

# ---- 1. system checks ------------------------------------------------------------------
step "1/7  System checks"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  ok "${PRETTY_NAME:-unknown OS}"
  case "${ID:-}${ID_LIKE:-}" in *kali*|*debian*|*ubuntu*) ;; *) warn "not a Debian-based system: apt steps may not apply" ;; esac
fi
command -v python3 >/dev/null 2>&1 || die "python3 not found: apt install python3"
PYVER="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python $PYVER found, 3.11 or newer is required"
ok "Python $PYVER"

# ---- 2. venv capability --------------------------------------------------------------
step "2/7  Virtual environment support"
# Debian/Kali ship python3 without ensurepip: "python3 -m venv" then creates a
# broken environment without pip. Test it for real in a throw-away directory.
venv_works() {
  local tmp rc
  tmp="$(mktemp -d)"
  if python3 -m venv "$tmp/probe" >/dev/null 2>&1 && "$tmp/probe/bin/python" -m pip --version >/dev/null 2>&1; then
    rc=0
  else
    rc=1
  fi
  rm -rf "$tmp"
  return "$rc"
}
if venv_works; then
  ok "python3 can create virtual environments with pip"
else
  warn "python3 cannot create a working virtual environment (python3-venv / python${PYVER}-venv missing)"
  if [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then die "install it as root: apt install python${PYVER}-venv"; fi
  if ask "Install python${PYVER}-venv with apt now? (uses sudo)" Y; then
    run $SUDO apt-get update -qq
    run $SUDO apt-get install -y "python${PYVER}-venv" || run $SUDO apt-get install -y python3-venv
    venv_works || die "virtual environments still do not work after installing the package"
    ok "virtual environment support installed"
  else
    die "cannot continue without virtual environment support"
  fi
fi

# ---- 3. create / reuse .venv -------------------------------------------------------------
step "3/7  Project virtual environment (.venv)"
venv_healthy() { [ -x "$VPY" ] && "$VPY" -m pip --version >/dev/null 2>&1; }
if [ -d "$VENV" ] && venv_healthy; then
  if ask "A working .venv already exists. Reuse it?" Y; then
    ok "reusing $VENV"
  else
    run rm -rf "$VENV"
  fi
elif [ -d "$VENV" ]; then
  warn ".venv exists but is broken (no python/pip inside)"
  ask "Delete and recreate it?" Y || die "cannot continue with a broken .venv"
  run rm -rf "$VENV"
fi
if [ ! -d "$VENV" ]; then
  ask "Create the virtual environment in $VENV?" Y || die "installation cancelled"
  run python3 -m venv "$VENV"
fi
"$VPY" -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)' || die ".venv is not an isolated environment"
venv_healthy || die "pip is not available inside .venv"
ok "$("$VPY" --version), $("$VPY" -m pip --version | cut -d' ' -f1-2), isolated from the system Python"

# ---- 4. core dependencies ------------------------------------------------------------------
step "4/7  Core dependencies (~60 MB)"
if ask "Install/update the core Python packages into .venv?" Y; then
  pip_install -q --upgrade pip wheel setuptools
  pip_install -q -e .
fi
"$VPY" -c 'import omomorfinder, httpx, dns, rich, bs4, lxml, PIL, numpy, mmh3, idna' \
  || die "core packages missing: rerun the installer and accept step 4"
ok "omomorfinder $("$VPY" -c 'import omomorfinder; print(omomorfinder.__version__)') and its dependencies import correctly"

# ---- 5. deep mode (optional) ----------------------------------------------------------------
step "5/7  Deep mode (optional): screenshots, OpenCV, multilingual NLP"
if [ -z "$DEEP" ]; then
  info "adds OpenCV, Playwright and PyTorch CPU + sentence-transformers (~1.5 GB on disk)"
  if ask "Install the deep-mode components?" N; then DEEP="yes"; else DEEP="no"; fi
fi
if [ "$DEEP" = "yes" ]; then
  pip_install -q torch --index-url https://download.pytorch.org/whl/cpu \
    || warn "CPU-only torch wheel failed: sentence-transformers will pull the default build"
  pip_install -q -e ".[deep]"
  ok "OpenCV, Playwright, sentence-transformers installed"
  info "headless Chromium (~150 MB) is used only to screenshot suspicious pages; no window is opened"
  if ask "Download headless Chromium now, with its system libraries? (apt, uses sudo)" Y; then
    if ! run "$VPY" -m playwright install --with-deps chromium; then
      warn "system libraries could not be installed, downloading the browser only"
      run "$VPY" -m playwright install chromium || warn "Chromium not installed: deep mode will skip screenshots"
    fi
  else
    info "skipped: it will be downloaded on the first --deep scan"
  fi
else
  info "skipped (fast and standard profiles work without it)"
fi

# ---- 6. launcher and PATH -------------------------------------------------------------------
step "6/7  Command 'omomorfinder'"
if ask "Create the launcher $LAUNCHER?" Y; then
  run mkdir -p "$HOME/.local/bin"
  printf '#!/usr/bin/env bash\nexec "%s" -m omomorfinder "$@"\n' "$VPY" > "$LAUNCHER"
  run chmod +x "$LAUNCHER"
  ok "launcher created"
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ok "~/.local/bin is already in PATH" ;;
    *)
      RC="$HOME/.bashrc"
      case "${SHELL:-}" in *zsh) RC="$HOME/.zshrc" ;; esac
      if ask "Add ~/.local/bin to PATH in $RC?" Y; then
        grep -qs 'HOME/.local/bin' "$RC" || printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC"
        ok "PATH updated in $RC (open a new terminal or run: source $RC)"
      else
        info "run it as $LAUNCHER, or add ~/.local/bin to PATH yourself"
      fi
      ;;
  esac
else
  info "skipped: run it as $VPY -m omomorfinder"
fi

# ---- 7. datasets, API keys, self-test -------------------------------------------------------
step "7/7  Datasets, API keys and self-test"
SETUP_ARGS=(--setup)
[ "$ASSUME_YES" -eq 1 ] && SETUP_ARGS+=(--yes)
run "$VPY" -m omomorfinder "${SETUP_ARGS[@]}" || warn "setup incomplete: datasets will be fetched on the first scan"
CFG="$HOME/.config/omomorfinder"
if [ ! -f "$CFG/.env" ]; then
  if ask "Create the API key template $CFG/.env (VirusTotal, AbuseIPDB, urlscan)?" Y; then
    run mkdir -p "$CFG"
    run cp .env.example "$CFG/.env"
    run chmod 600 "$CFG/.env"
    info "edit it to enable the optional services: nano $CFG/.env"
  fi
else
  ok "API key file already present: $CFG/.env"
fi
"$VPY" -m omomorfinder --version >/dev/null || die "self-test failed: omomorfinder does not start"
ok "self-test passed: $("$VPY" -m omomorfinder --version)"

printf '\n%s%sdone.%s  try:  %somomorfinder example.com%s   %s(help: omomorfinder --help)%s\n\n' \
  "$B" "$OK" "$R" "$C1" "$R" "$DIM" "$R"
