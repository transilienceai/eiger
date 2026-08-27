# Eiger Operations (S1 seed)

The **image is the unit of change** — fix code, rebuild the image, redeploy. Never hand-patch a running container.

> **M3 knowledge base is ephemeral (in-process ChromaDB).** Participant-submitted KB entries live only in the web container's memory. A web-container restart (or `docker compose up -d web`) wipes submitted content back to the seeded fixtures — a participant mid-M3 must resubmit their poison. Graded progress is unaffected (it lives in the audit log / external progress store). The embedding model is baked into the image, so the first `/api/ask` does not require a runtime download.

> **M6 adds two MCP servers** (`mcp-core-banking`, `mcp-crm`) as their own containers, built from the same image. `web` **discovers them from `mcp.json`** (baked into the image at `/app/mcp.json`) — the source of truth, like a real MCP client. Per-server env overrides `MCP_CORE_URL`/`MCP_CRM_URL` still win if set. **Single-process deploys** (pure-local `python`, a single-container cloud/Modal instance with no reachable MCP containers) must set **`MCP_IN_PROCESS=1`** to run the servers in-memory instead of dialling the `mcp.json` URLs — otherwise the app tries `http://mcp-core-banking:9001/mcp` and fails. (The 5-container compose reaches those URLs fine, so it needs no flag.) **Their ports (`9001`/`9002`) are also published** so participants can point **MCP Inspector** (Streamable-HTTP at `/mcp`) at them for the "see the poison on the wire" demo — this network exposure of unauthenticated MCP is deliberate (it *is* the M6 lesson). On the cloud host these ports must be opened in the security group / Modal exposure alongside `:8000`; on a dev box the uncommitted override pins them to `127.0.0.1`. `/api/mcp-agent` is **BYOK** for the real poisoning attack (send a `provider`+`api_key`); the keyless llama floor demonstrates the plumbing but won't autonomously chain the poisoned tool description. Known single-shot demo caveat: on a *shared* `mcp-crm`, the M6 rug-pull description permanently mutates after the first `list_tools` (per-participant MCP isolation resolves this — Ops slice).

> **M7 adds a LangGraph dispute pipeline reachable at `POST /api/dispute`.** It runs **in-process inside the existing `web` service** — no new container, no compose change, no new port. Nothing to deploy or redeploy differently versus M1–M6.

> **M8 adds `POST /api/guarded-chat`** (the guardrail-fronted chatbot) **and retains `GET /capstone`** as a legacy, read-only residual-risk API aggregating each module's core-exploit event across m1–m8. That JSON route is not the Treasury Heist learner capstone. Both run **in-process inside the existing `web` service** — no new container, no compose change, no new port.

> **S11 (the treasury-heist capstone) adds six routes** — `/source/tree`, `/source/blob`, `/treasury/brief`, `/ingest/docs` (GET + POST), `/ingest/delete`, `/api/treasury/review` — **and one flag**: `SEC_SECRET_SCANNING`. All of it runs **in-process inside the existing `web` service** — no new container, no compose change, no new port. The capstone: a leaked ingest key lets a participant publish a fake policy document that has to out-rank a seeded corpus in the treasury agent's retrieval, so it gets read as authoritative policy and the agent is talked into releasing funds to their account. Two things to know before you touch a flag mid-session or redeploy:
> - **`HALCYON_MODE=secure` disables the capstone entirely** — `SEC_SECRET_SCANNING` on redacts the leaked key everywhere `/source/blob` would otherwise serve it, so no key ever leaks, so nothing can ever be ingested, so there's nothing for the agent to retrieve. Run the capstone in `vulnerable` mode (the Day-2 default). Unlike M4's `SEC_ARTIFACT_VERIFICATION`, `SEC_SECRET_SCANNING` is NOT shared with any other module — flipping it only affects the capstone.
> - **A mid-session redeploy rotates the ingest key AND the assigned attacker account, and reassigns the scenario** (all in-process `TreasuryProvider` state, not persisted) — so the brief a participant is looking at silently stops matching what the agent actually retrieves against, and a key or account they copied before the redeploy is stale. Earned progress is safe: a landed transfer banks a durable `CHAIN_CORE_PASSED` audit-log event the instant it lands (both in `/api/treasury/review`'s own handler and via the Capstone tab's automatic background call to `/validate/chain`), so it survives a redeploy even without a participant ever clicking Validate. **Recovery for anyone still mid-attempt: tell them to reload the Capstone tab** — it re-fetches `/treasury/brief` (new brief + new account) and they should re-read `.env.sample` in the source browser for the new key. Still tell participants to click **Validate** after every review as good practice — the pass is banked automatically, but Validate is how they confirm it landed.

> **Compose project name.** From the repo directory these commands run under the project **`eiger`** (the directory name), so a bare `docker compose …` is correct — confirm with `docker compose ls`. Two gotchas: (1) a **legacy `halcyon`-named stack** on the same box (early dev boxes) will collide on `:11434` — `docker compose -p halcyon down` it first; (2) a local, uncommitted `docker-compose.override.yml` may remap host ports (e.g. web → `8010`) to dodge collisions with other containers — adjust the health-check URL to match.

## Deploy all (local-LAN or cloud host — same images)
    docker compose up -d --build          # 5 services: web, db, ollama, mcp-core-banking, mcp-crm
    docker compose exec ollama ollama pull llama3.1:8b   # first run only

## Health-check who's up
    curl -s localhost:8000/health | jq          # host port may be remapped by an override (e.g. 8010)
    # expect: {"status":"ok","mode":"...","ollama":"up","db":"up","mcp":"up"}
    # "mcp": "up" (both MCP servers reachable) | "down" (one/both unreachable) | "in-process" (no MCP_*_URL set)

## Redeploy after a code fix (rebuild image, keep db/ollama volumes)
    docker compose up -d --build web mcp-core-banking mcp-crm   # rebuild all 3 app services (shared image)

_Reset-one-participant and nuke-and-reprovision land in the Ops slice once the per-participant fleet exists. S1 runs a single app instance against shared db + ollama._

## Gandalf warm-up (separate Modal app — self-serve for the room)
The M0 Gandalf lab (`labs/m0-gandalf/gandalf_lakera_proxy.py`, a keyless threaded proxy to Lakera's public Gandalf API) is deployed as its **own** Modal web app so participants play it themselves — independent of the Eiger stack.

    modal deploy deploy/modal_gandalf.py     # prints a public https://…modal.run URL — share it with the room

One warm container serves the whole room (proxy is threaded; work is just I/O). **Accepted risk:** single egress IP to Lakera's shared public API → if it throttles/blocks, fall back to running it on screen. Nothing here touches the Eiger app/db/ollama.

---

## AWS single-instance host (proven config — S1)

A single EC2 box runs the whole `docker compose` stack, bootstrapped from the public repo. This is the S1 host; the 22-container fleet is a later Ops slice.

### ⚠️ Hard-won constraints (do not skip)
- **USE AN AMD INSTANCE** (`r6a`/`m6a`), or a non-AMX Intel gen (`r6i`/`m6i`, Ice Lake). **Do NOT use Intel Sapphire-Rapids "i"-suffix families (`r7i`/`m7i`/`c7i`)** — they expose **Intel AMX**, and Ollama's `llama-server` **segfaults on AMX under virtualization** (crashes every model, every Ollama version — not OOM, not a timeout). This cost us a full relaunch.
- **Account quota:** `sara-sales` has a **5-vCPU Standard On-Demand limit** in ap-south-1, so max instance is **4 vCPU** (an 8-vCPU `*.2xlarge` is rejected with `VcpuLimitExceeded`). Request a quota increase (Service Quotas → "Running On-Demand Standard instances") for anything bigger, or for the multi-instance fleet.
- CPU inference of `llama3.1:8b` on 4 vCPU works but is slow (~6 s cold model-load, then a few seconds/reply). Fine for demo/single-user. For a snappy 22-person Day-1, get a **GPU instance** (e.g. `g5.xlarge`, needs a separate "Running On-Demand G" quota) — CUDA also sidesteps the AMX bug.
- Security group opens `8000` (app) + `22` (ssh) **+ `9001`/`9002` (MCP servers, for the M6 Inspector demo)**. Ollama port `11434` stays **closed** — keep it that way. Note `9001`/`9002` expose unauthenticated MCP that can move seeded money on a per-session bank; that exposure is deliberate (the M6 lesson) and contained by per-session fixtures + `/reset`, but keep the host ephemeral and don't reuse it for anything real.

### Proven parameters (account 331145994818, region ap-south-1)
| Thing | Value |
|---|---|
| AWS profile | `sara-sales` |
| Region | `ap-south-1` |
| Instance type | `r6a.xlarge` (AMD, 4 vCPU, 32 GB, ~$0.24/hr) |
| AMI | Ubuntu 24.04 — resolve latest via SSM (below), don't hardcode |
| Key pair | `eiger` |
| Security group | inbound tcp `8000` + `22` from `0.0.0.0/0` |
| Disk | 40 GB gp3 |
| Bootstrap | user-data clones `github.com/kkmookhey/eiger`, `docker compose up -d --build`, pulls `llama3.1:8b` |

### Deploy (one-time infra + launch)
```bash
P="--profile sara-sales --region ap-south-1"
AMI=$(aws ssm get-parameter $P --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)
SUBNET=$(aws ec2 describe-subnets $P --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
VPC=$(aws ec2 describe-subnets $P --subnet-ids $SUBNET --query 'Subnets[0].VpcId' --output text)
aws ec2 create-key-pair $P --key-name eiger --query KeyMaterial --output text > eiger-key.pem && chmod 600 eiger-key.pem
SG=$(aws ec2 create-security-group $P --group-name eiger-sg --description "Eiger lab" --vpc-id $VPC --query GroupId --output text)
aws ec2 authorize-security-group-ingress $P --group-id $SG --ip-permissions \
  IpProtocol=tcp,FromPort=8000,ToPort=8000,IpRanges='[{CidrIp=0.0.0.0/0}]' \
  IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]'
aws ec2 run-instances $P --image-id $AMI --instance-type r6a.xlarge \
  --key-name eiger --security-group-ids $SG --subnet-id $SUBNET --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":40,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --user-data file://deploy/aws-userdata.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=eiger}]'
# then: aws ec2 describe-instances $P --filters Name=tag:Name,Values=eiger Name=instance-state-name,Values=running --query 'Reservations[].Instances[].PublicIpAddress' --output text
# lab comes up at http://<public-ip>:8000/ after ~10-15 min (docker install + build + model pull)
```
The user-data bootstrap script is versioned at `deploy/aws-userdata.sh`.

### Redeploy a code fix to the running box (no relaunch)
```bash
ssh -i eiger-key.pem ubuntu@<ip> 'cd /opt/eiger && sudo git pull --ff-only && sudo docker compose up -d --build web'
```

### Teardown
```bash
P="--profile sara-sales --region ap-south-1"
IID=$(aws ec2 describe-instances $P --filters Name=tag:Name,Values=eiger Name=instance-state-name,Values=running,pending --query 'Reservations[].Instances[].InstanceId' --output text)
aws ec2 terminate-instances $P --instance-ids $IID
aws ec2 wait instance-terminated $P --instance-ids $IID
aws ec2 delete-security-group $P --group-name eiger-sg
aws ec2 delete-key-pair $P --key-name eiger
```
Or just **stop** (not terminate) to pause billing while keeping the box: `aws ec2 stop-instances $P --instance-ids $IID`.
