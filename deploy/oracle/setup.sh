#!/usr/bin/env bash
# TxShield single-VM setup (Ubuntu 22.04/24.04, x86_64 or ARM64; written for
# Oracle Cloud Always Free Ampere instances).
#
#   git clone https://github.com/pri-3x/txshield.git && cd txshield
#   deploy/oracle/setup.sh            # installs Docker, opens 80/443, writes .env
#   nano deploy/oracle/.env           # set TXSHIELD_RPC_URLS (your Sepolia RPC URL)
#   deploy/oracle/setup.sh            # builds and starts the stack
#
# Safe to re-run. Secrets are generated once into deploy/oracle/.env
# (mode 600) and never printed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ENV_FILE="$HERE/.env"
COMPOSE=(docker compose -f "$HERE/docker-compose.yml" --env-file "$ENV_FILE")

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run as your normal user (it uses sudo where needed), not as root"
command -v apt-get >/dev/null || die "this script supports Ubuntu/Debian only"

# --- packages ---------------------------------------------------------------
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  say "Installing Docker (Ubuntu packages), git, openssl"
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 git openssl curl
  sudo systemctl enable --now docker
fi
if ! id -nG "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  say "Added $USER to the docker group. Log out and back in (or run: newgrp docker), then re-run this script."
  exit 0
fi

# --- firewall ---------------------------------------------------------------
# Oracle's Ubuntu images ship iptables rules that reject everything except
# SSH. Allow HTTP/HTTPS (also open them in the VCN security list).
if command -v iptables >/dev/null; then
  changed=0
  for rule in "-p tcp --dport 80" "-p tcp --dport 443" "-p udp --dport 443"; do
    # shellcheck disable=SC2086
    if ! sudo iptables -C INPUT $rule -m state --state NEW -j ACCEPT 2>/dev/null; then
      # shellcheck disable=SC2086
      sudo iptables -I INPUT 5 $rule -m state --state NEW -j ACCEPT && changed=1
    fi
  done
  if [ "$changed" = 1 ]; then
    say "Opened ports 80/443 in the VM firewall"
    if ! command -v netfilter-persistent >/dev/null; then
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    fi
    sudo netfilter-persistent save
  fi
fi

# --- configuration ------------------------------------------------------------
rand() { openssl rand -hex "$1"; }
if [ ! -f "$ENV_FILE" ]; then
  ip="${PUBLIC_IP:-$(curl -fsS --max-time 10 https://checkip.amazonaws.com | tr -d '[:space:]')}"
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not detect the public IPv4 address; run again with PUBLIC_IP=<address>"
  dashed="${ip//./-}"
  say "Writing $ENV_FILE (secrets generated here, never printed)"
  umask 077
  cat >"$ENV_FILE" <<EOF
# TxShield production settings. Keep this file private (mode 600).

# Required: your Sepolia RPC endpoint (e.g. Alchemy or Infura), as chainId=url.
# Example: TXSHIELD_RPC_URLS=11155111=https://eth-sepolia.g.alchemy.com/v2/<your-key>
TXSHIELD_RPC_URLS=

# Public hostnames (sslip.io resolves them to this VM; no domain needed).
API_HOST=api.${dashed}.sslip.io
APP_HOST=app.${dashed}.sslip.io

POSTGRES_PASSWORD=$(rand 24)
# API keys: the first is the dashboard's, the second is for the browser
# extension and other clients. Add more, comma-separated, to give out keys.
TXSHIELD_DASHBOARD_API_KEY=dash-$(rand 20)
TXSHIELD_CLIENT_API_KEY=client-$(rand 20)
TXSHIELD_API_KEYS=\${TXSHIELD_DASHBOARD_API_KEY},\${TXSHIELD_CLIENT_API_KEY}
# Dashboard login (HTTP Basic auth): user "admin".
TXSHIELD_DASHBOARD_BASIC_AUTH=admin:$(rand 16)
TXSHIELD_VERSION=$(git -C "$REPO" describe --tags --always 2>/dev/null || echo dev)
EOF
  chmod 600 "$ENV_FILE"
fi

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a
if [ -z "${TXSHIELD_RPC_URLS:-}" ]; then
  say "Almost done. Edit $ENV_FILE and set TXSHIELD_RPC_URLS to your Sepolia RPC URL, then run this script again."
  exit 0
fi
[[ "$TXSHIELD_RPC_URLS" =~ ^[0-9]+=https:// ]] || die "TXSHIELD_RPC_URLS must look like 11155111=https://..."

# --- build and start ------------------------------------------------------------
say "Building and starting TxShield (the first build takes several minutes)"
export TXSHIELD_VERSION="$(git -C "$REPO" describe --tags --always 2>/dev/null || echo dev)"
"${COMPOSE[@]}" up -d --build

say "Waiting for the API"
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T api /usr/local/bin/txshield healthcheck --url http://127.0.0.1:8080/livez >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 5
done
[ "${ok:-0}" = 1 ] || die "the API did not become healthy; check: docker compose -f $HERE/docker-compose.yml logs api"

cat <<EOF

TxShield is running.

  Dashboard:  https://${APP_HOST}      (user "admin"; password in $ENV_FILE)
  API:        https://${API_HOST}      (send "Authorization: Bearer <TXSHIELD_CLIENT_API_KEY>")

HTTPS certificates are issued on the first request and can take a minute.
For the browser extension: API URL https://${API_HOST}, API key = TXSHIELD_CLIENT_API_KEY,
dashboard URL https://${APP_HOST}. Read the values with: cat $ENV_FILE
EOF
