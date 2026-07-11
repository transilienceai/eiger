#!/bin/bash
# EC2 user-data: bootstrap a single-instance Halcyon host from the public repo.
# See OPERATIONS.md → "AWS single-instance host" for the launch command + constraints.
# IMPORTANT: run this on an AMD or non-AMX Intel instance (Ollama segfaults on Intel AMX).
exec > /var/log/halcyon-bootstrap.log 2>&1
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git curl
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
cd /opt
git clone https://github.com/kkmookhey/eiger.git
cd eiger
HALCYON_MODE=vulnerable docker compose up -d --build
# wait for the ollama server to accept connections
for i in $(seq 1 60); do
  if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then break; fi
  sleep 5
done
# pull the Day-1 model into the shared ollama volume
docker compose exec -T ollama ollama pull llama3.1:8b
touch /var/log/halcyon-bootstrap.done
