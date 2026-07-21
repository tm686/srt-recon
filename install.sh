#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
step() { echo -e "${YELLOW}[>]${NC} $1"; }

ROOT="$(cd "$(dirname "$0")" && pwd)"
CONF="$ROOT/srt-recon.conf"

# ── VDI/proxy SSL fix ────────────────────────────────────────────────
# Corporate VDIs often MITM HTTPS traffic. We grab the proxy's CA cert
# and install it so Go, uv, curl, and npm all trust it.
fix_ssl() {
    # Always set these as fallbacks
    export GIT_SSL_NO_VERIFY=1
    export GONOSUMCHECK="*"
    export GONOSUMDB="*"
    export GOINSECURE="*"
    export GOPROXY="direct"
    export NODE_TLS_REJECT_UNAUTHORIZED=0
    if ! grep -q "^insecure" ~/.curlrc 2>/dev/null; then
        echo "insecure" >> ~/.curlrc
    fi

    # Try to capture the proxy's CA cert and install it system-wide
    if ! openssl s_client -connect pypi.org:443 -servername pypi.org </dev/null 2>/dev/null | openssl x509 -noout 2>/dev/null; then
        info "SSL verification works already, skipping proxy cert install"
        return
    fi

    # Extract the proxy/MITM CA cert (last cert in the chain)
    local proxy_cert
    proxy_cert=$(echo | openssl s_client -connect pypi.org:443 -servername pypi.org -showcerts 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{ print }' | tail -n +1)

    if [ -n "$proxy_cert" ] && [ ! -f /usr/local/share/ca-certificates/vdi-proxy.crt ]; then
        step "Installing VDI proxy CA certificate into system trust store..."
        echo "$proxy_cert" | sudo tee /usr/local/share/ca-certificates/vdi-proxy.crt >/dev/null 2>&1
        sudo update-ca-certificates 2>/dev/null && log "Proxy CA cert installed" || warn "Could not install proxy cert (no sudo?)"
    fi

    # Point Go and Python at the system bundle
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
        export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
        export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
    fi
}
fix_ssl

# ── Load config if present ───────────────────────────────────────────
if [ -f "$CONF" ]; then
    info "Loading config from $CONF"
    # shellcheck source=/dev/null
    source "$CONF"
else
    info "No srt-recon.conf found, using defaults (copy srt-recon.conf.example to customize)"
fi

# Defaults (overridden by conf)
GO_TOOLS_PATH="${GO_TOOLS_PATH:-$HOME/go/bin}"
SECLISTS_PATH="${SECLISTS_PATH:-/usr/share/seclists}"
SKIP_GO_TOOLS="${SKIP_GO_TOOLS:-0}"
SKIP_SYSTEM_CHECK="${SKIP_SYSTEM_CHECK:-0}"
OFFLINE_MODE="${OFFLINE_MODE:-0}"

# ── Prerequisite check ───────────────────────────────────────────────
check_prereqs() {
    log "Checking prerequisites..."
    local missing=()

    command -v python3 &>/dev/null || missing+=("python3")
    command -v node &>/dev/null || missing+=("node (>=18)")
    command -v npm &>/dev/null || missing+=("npm")
    command -v git &>/dev/null || missing+=("git")

    if [ ${#missing[@]} -gt 0 ]; then
        warn "Missing prerequisites: ${missing[*]}"
        echo ""
        echo "Install them with:"
        echo "  sudo apt update && sudo apt install -y python3 nodejs npm git"
        exit 1
    fi

    # Check uv
    if ! command -v uv &>/dev/null; then
        step "Installing uv (Python package manager)..."
        curl -kLsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    fi
    info "uv: $(command -v uv)"

    # Check Go (optional, for tool install)
    if command -v go &>/dev/null; then
        info "go: $(go version)"
    else
        warn "Go not found - Go tools will be skipped"
        SKIP_GO_TOOLS="1"
    fi
}

# ── Go tools ─────────────────────────────────────────────────────────
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/haccer/subjack@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/ffuf/ffuf/v2@latest"
)

install_go_tools() {
    if [ "$SKIP_GO_TOOLS" = "1" ] || [ "$OFFLINE_MODE" = "1" ]; then
        info "Skipping Go tool installation"
        return
    fi
    log "Installing Go tools to $GO_TOOLS_PATH..."
    export GOPATH="${GOPATH:-$HOME/go}"
    export GOBIN="$GO_TOOLS_PATH"
    mkdir -p "$GO_TOOLS_PATH"

    for tool in "${GO_TOOLS[@]}"; do
        name=$(basename "${tool%%@*}")
        if [ -f "$GO_TOOLS_PATH/$name" ]; then
            info "$name already installed"
        else
            step "Installing $name..."
            go install "$tool" 2>/dev/null || warn "Failed to install $name"
        fi
    done

    # Add to PATH hint
    if [[ ":$PATH:" != *":$GO_TOOLS_PATH:"* ]]; then
        echo ""
        info "Add Go tools to PATH (add to ~/.bashrc or ~/.zshrc):"
        echo "  export PATH=\"$GO_TOOLS_PATH:\$PATH\""
    fi
}

# ── System tool check ────────────────────────────────────────────────
check_system_tools() {
    if [ "$SKIP_SYSTEM_CHECK" = "1" ]; then return; fi
    log "Checking system tools..."
    local tools=(nmap rustscan)
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            info "$tool: $(command -v "$tool")"
        else
            warn "$tool not found (optional)"
        fi
    done

    # Check SecLists
    if [ -d "$SECLISTS_PATH" ]; then
        info "SecLists found at $SECLISTS_PATH"
    else
        warn "SecLists not found at $SECLISTS_PATH"
        echo "  Install: sudo apt install seclists"
        echo "  Or:      git clone https://github.com/danielmiessler/SecLists $SECLISTS_PATH"
    fi
}

# ── Bundled wordlists ────────────────────────────────────────────────
install_wordlists() {
    if [ -f "$ROOT/wordlists/ffuf-wordlist-5000.txt" ]; then
        info "Bundled wordlists already present"
        return
    fi
    log "Downloading bundled wordlists..."
    mkdir -p "$ROOT/wordlists"
    for f in ffuf-wordlist-5000.txt ffuf-wordlist-default-long.txt ffuf-wordlist-default-small.txt; do
        step "Fetching $f..."
        curl -skL "https://raw.githubusercontent.com/R-s0n/ars0n-framework-v2/main/wordlists/$f" -o "$ROOT/wordlists/$f" \
            || warn "Failed to download $f"
    done
    log "Wordlists ready"
}

# ── Backend ──────────────────────────────────────────────────────────
install_backend() {
    log "Setting up Python backend..."
    cd "$ROOT/backend"
    uv sync --native-tls || uv sync --allow-insecure-host pypi.org --allow-insecure-host files.pythonhosted.org
    log "Backend ready"
}

# ── Frontend ─────────────────────────────────────────────────────────
install_frontend() {
    log "Setting up frontend..."
    cd "$ROOT/frontend"
    npm install --silent 2>/dev/null || npm install --strict-ssl=false --silent
    log "Frontend ready"
}

# ── Generate config ──────────────────────────────────────────────────
generate_config() {
    if [ ! -f "$CONF" ]; then
        step "Generating srt-recon.conf from example..."
        cp "$ROOT/srt-recon.conf.example" "$CONF"
        # Auto-detect Go tools path
        if command -v go &>/dev/null; then
            sed -i "s|GO_TOOLS_PATH=.*|GO_TOOLS_PATH=\"$GO_TOOLS_PATH\"|" "$CONF"
        fi
        log "Config written to $CONF (edit as needed)"
    fi
}

# ── Initialize git repo ──────────────────────────────────────────────
init_git() {
    cd "$ROOT"
    if [ ! -d ".git" ]; then
        step "Initializing git repository..."
        git init -q
        git add -A
        git commit -q -m "Initial SRT-Recon setup"
        log "Git repo initialized"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      SRT-Recon Installer v0.1.0      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""

check_prereqs
echo ""
generate_config
echo ""
install_go_tools
echo ""
check_system_tools
echo ""
install_wordlists
echo ""
install_backend
echo ""
install_frontend
echo ""
init_git
echo ""
log "Installation complete!"
echo ""
echo -e "  Start:  ${CYAN}./run.sh${NC}"
echo -e "  Config: ${CYAN}$CONF${NC}"
echo -e "  Open:   ${CYAN}http://127.0.0.1:5173${NC}"
echo ""
