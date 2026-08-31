# Eiger operations

Eiger is deliberately vulnerable training software. Operate every instance as though it
is already compromised. It must never share a host, network, cloud identity, credentials,
or data with a production or personal environment.

## Local workstation

The default Compose configuration is host-local:

| Service | Host exposure |
|---|---|
| Learner UI | `127.0.0.1:8000` |
| MCP core-banking | `127.0.0.1:9001` |
| MCP CRM | `127.0.0.1:9002` |
| PostgreSQL | Compose network only |
| Ollama | Compose network only |

Start the stack:

```bash
docker compose up -d --build
docker compose exec ollama ollama pull llama3.1:8b
curl -fsS http://127.0.0.1:8000/health
```

Open `http://127.0.0.1:8000/`. MCP Inspector can connect to the two host-local MCP
endpoints at `http://127.0.0.1:9001/mcp` and `http://127.0.0.1:9002/mcp`.

Rebuild all application services after a code change:

```bash
docker compose up -d --build web mcp-core-banking mcp-crm
```

Inspect or stop the stack:

```bash
docker compose ps
docker compose logs --tail=100 web
docker compose down
```

`docker compose down -v` also deletes the local database and model volumes. Use it only
when you intentionally want a complete reset.

## Isolated classroom deployment

The supported classroom shape is one disposable application instance per participant,
with no route to production or internal networks. Keep the Compose ports host-local and
put authenticated access in front of the host using a private VPN, SSH tunnel, or an
equivalent controlled ingress layer.

Minimum controls:

- Use a throwaway host or dedicated cloud project with no reusable workload identity.
- Block the cloud metadata endpoint (`169.254.169.254`) from every Eiger container.
- Deny access to production networks, internal services, and real data stores.
- Use only synthetic fixtures. Never inject real credentials or customer data.
- If participants use BYOK, require disposable keys with spend caps and revoke them after
  the session.
- Give every participant a separate app, database state, and MCP-server pair.
- Destroy the environment after the teaching session.

For a trusted, isolated private LAN, you can deliberately bind the learner UI to one
private interface:

```bash
EIGER_WEB_BIND=10.0.0.25 docker compose up -d --build
```

Replace `10.0.0.25` with the host's actual private-LAN address and restrict the host
firewall to the classroom subnet. Do not use `0.0.0.0`, and do not expose port 8000 to
the public internet.

MCP ports remain host-local unless the M6 wire-protocol exercise requires remote MCP
Inspector access. In that case, bind them deliberately and limit the firewall to the
instructor or classroom subnet:

```bash
EIGER_WEB_BIND=10.0.0.25 EIGER_MCP_BIND=10.0.0.25 docker compose up -d --build
```

Ports 9001 and 9002 are unauthenticated, deliberately vulnerable MCP services. Never
publish them beyond the isolated lab network. PostgreSQL and Ollama remain internal to
the Compose network in all cases.

## Runtime behavior that matters operationally

- The M3 ChromaDB knowledge base is in-process. Restarting the web container clears
  participant-submitted M3 documents, while graded progress in PostgreSQL remains.
- M6 uses two standalone MCP containers discovered from `mcp.json`. A pure single-process
  deployment must set `MCP_IN_PROCESS=1` instead.
- A shared M6 CRM container has process-global rug-pull state. Per-participant MCP
  containers preserve the intended reset and isolation behavior.
- The Treasury Heist scenario and ingest key are in-process. Restarting the web container
  rotates unfinished scenarios; participants should reload the Capstone tab.
- `HALCYON_MODE=secure` enables `SEC_SECRET_SCANNING`, which intentionally prevents the
  Treasury Heist's initial key leak. Run that capstone in vulnerable mode.

## Port conflicts

Create an uncommitted `docker-compose.override.yml` and keep every published port bound to
`127.0.0.1`. For example:

```yaml
services:
  web:
    ports: !override ["127.0.0.1:8010:8000"]
  mcp-core-banking:
    ports: !override ["127.0.0.1:9101:9001"]
  mcp-crm:
    ports: !override ["127.0.0.1:9102:9002"]
```

The Compose project name defaults to the repository directory name, `eiger`. A legacy
stack started with another project name can be located with `docker compose ls` and
stopped by passing that exact project name with `-p`.
