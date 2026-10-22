#!/bin/bash
set -euo pipefail
exec 9>/var/lock/new-api-dev-bootstrap.lock
flock -n 9 || exit 0
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io docker-compose-v2 ca-certificates curl openssl python3
systemctl enable --now docker
install -d -m 0700 /opt/new-api-dev
touch /opt/new-api-dev/host-ready
