#!/usr/bin/env bash
# One-step install on a Linux server. Copy this folder to the server, then inside it run:
#
#   bash install.sh                        ->  https://<server-ip>.sslip.io/dashboard   (HTTPS, no domain needed)
#   bash install.sh gateway.example.com    ->  https://gateway.example.com/dashboard    (your own domain)
#   bash install.sh --http-only            ->  http://<server-ip>:8080/dashboard        (testing only: not encrypted)
#
# HTTPS certificates are free and automatic. Allow ports 80 and 443 in the server's firewall.
# For your own domain, first point its DNS A record at this server.
# Safe to run again (e.g. after copying in new files): keys, history and the chosen address are kept.
set -euo pipefail
cd "$(dirname "$0")"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"

touch .env
current() { grep -m1 "^$1=" .env 2>/dev/null | cut -d= -f2- || true; }
case "${1:-}" in
  --http-only) DOMAIN="" ;;
  "")
    DOMAIN="$(current DOMAIN)"
    if [ -z "$DOMAIN" ]; then
      IP="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)"
      if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        DOMAIN="${IP//./-}.sslip.io"   # a free hostname that points at this IP, so HTTPS works without a domain
      else
        echo "Couldn't find this server's public IP; installing without HTTPS. Re-run: bash install.sh your-domain.com" >&2
      fi
    fi ;;
  *) DOMAIN="$1" ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "==> Installing Docker"
  if ! curl -fsSL https://get.docker.com | $SUDO sh; then
    # get.docker.com asks for optional plugins that older releases (e.g. Ubuntu 20.04) don't have;
    # it has already added Docker's apt repository, so install just the packages we need.
    echo "==> Retrying with the core Docker packages"
    $SUDO apt-get update -qq
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
  fi
fi
DOCKER="docker"
docker info >/dev/null 2>&1 || DOCKER="$SUDO docker"
if ! $DOCKER compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 (the 'docker compose' command) is required." >&2
  exit 1
fi

# Small servers (e.g. Oracle's free 1 GB VM.Standard.E2.1.Micro) can run out of memory while building;
# add 2 GB of swap once if the machine has under 2 GB RAM and no swap yet.
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)
if [ "$MEM_MB" -lt 2000 ] && [ -z "$(swapon --show 2>/dev/null)" ] && [ ! -f /swapfile ]; then
  echo "==> Low memory (${MEM_MB} MB): adding 2 GB swap"
  $SUDO fallocate -l 2G /swapfile 2>/dev/null || $SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  $SUDO chmod 600 /swapfile && $SUDO mkswap /swapfile >/dev/null && $SUDO swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab >/dev/null
fi

# Open the web ports in the server's own firewall. Oracle Cloud's Ubuntu images block everything except SSH
# with iptables even after you open ports in the cloud console; ufw may be on elsewhere.
if command -v iptables >/dev/null 2>&1 && $SUDO iptables -S INPUT 2>/dev/null | grep -q -- "-j REJECT"; then
  echo "==> Opening ports 80 and 443 in the server firewall"
  for p in 80 443; do
    $SUDO iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || $SUDO iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
  done
  if command -v netfilter-persistent >/dev/null 2>&1; then $SUDO netfilter-persistent save >/dev/null 2>&1 || true; fi
fi
if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  $SUDO ufw allow 80/tcp >/dev/null && $SUDO ufw allow 443/tcp >/dev/null
fi

set_env() {  # set_env KEY VALUE: replace the line if present, else append
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}

PROFILE=()
if [ -n "$DOMAIN" ]; then
  set_env DOMAIN "$DOMAIN"
  set_env PUBLIC_URL "https://$DOMAIN"
  set_env BIND_ADDR 127.0.0.1          # only reachable through HTTPS
  PROFILE=(--profile https)
  URL="https://$DOMAIN"
else
  set_env DOMAIN ""
  set_env BIND_ADDR 0.0.0.0
  URL="http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo SERVER-IP):$(current HOST_PORT | grep . || echo 8080)"
fi
compose() { $DOCKER compose ${PROFILE[@]+"${PROFILE[@]}"} "$@"; }

echo "==> Building"
compose build --quiet
echo "==> Setting up keys"
compose run --rm --no-deps gateway python server.py init
echo "==> Starting"
compose up -d

printf "==> Waiting for it to come up"
for _ in $(seq 1 30); do
  if compose exec -T gateway python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)" >/dev/null 2>&1; then
    echo " ok"
    cat <<EOF

Squidbrake is running, and restarts by itself after crashes and reboots.

  Dashboard:   $URL/dashboard
  Keys:        shown above the first time (save them). Make more with:
                 $DOCKER compose exec gateway python server.py add-key NAME             (an agent)
                 $DOCKER compose exec gateway python server.py add-key NAME --approver  (a person)
  Rules:       edit rules.yaml in this folder; changes apply within seconds
  Logs:        $DOCKER compose logs -f gateway
EOF
    if [ -z "$DOMAIN" ]; then
      echo "  Note:        this is plain HTTP (not encrypted). For HTTPS run: bash install.sh"
    else
      printf "==> Checking %s from the internet (getting the certificate can take a minute)" "$URL"
      for _ in $(seq 1 30); do
        if curl -fsS --max-time 10 "$URL/health" >/dev/null 2>&1; then echo " ok"; exit 0; fi
        printf "."; sleep 4
      done
      echo
      echo "  Not reachable yet over HTTPS. Allow ports 80 and 443 in your cloud provider's firewall," >&2
      echo "  then check: $DOCKER compose --profile https logs caddy" >&2
    fi
    exit 0
  fi
  printf "."; sleep 2
done
echo
echo "It didn't come up in time. See: $DOCKER compose logs gateway" >&2
exit 1
