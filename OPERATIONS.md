# Halcyon Operations (S1 seed)

The **image is the unit of change** — fix code, rebuild the image, redeploy. Never hand-patch a running container.

## Deploy all (local-LAN or cloud host — same images)
    docker compose up -d --build
    docker compose exec ollama ollama pull llama3.1:8b   # first run only

## Health-check who's up
    curl -s localhost:8000/health | jq
    # expect: {"status":"ok","mode":"...","ollama":"up","db":"up"}

## Redeploy after a code fix (rebuild image, keep db/ollama volumes)
    docker compose up -d --build web

_Reset-one-participant and nuke-and-reprovision land in the Ops slice once the per-participant fleet exists. S1 runs a single app instance against shared db + ollama._
