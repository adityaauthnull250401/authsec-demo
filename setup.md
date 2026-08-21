# AuthSec demo setup and operations

Use this document only when provisioning, restarting, repairing, or explaining the setup.
For the meeting, use `pitch.md`. For code and protocol internals, use `implementation.md`.

## Current machine status

This checkout is already provisioned. The local `.env` is complete, including the verified
M2M Client ID, private-key path, and key ID. Normal operation does not require copying a
Client ID from AuthSec again.

The non-secret anchors are:

| Object | Current value |
|---|---|
| AuthSec issuer | `https://app.authsec.ai` |
| Workspace ID | `41c3ab74-3393-4a2f-abd2-4245fcd8f690` |
| Application | `GitHub MCP Demo` |
| Application ID | `43fc5060-2dca-482a-b69c-1890de19c3ff` |
| Resource URI | `https://mcp-demo.mcpauthz.com/mcp` |
| M2M Service Account | `svc-github-ci` |
| M2M Client ID | `dec85d83-7660-465c-93d4-aa41128f3d91` |
| M2M key ID | `demo-28d3f699c31e` |
| M2M public JWKS | `https://mcp-demo.mcpauthz.com/.well-known/m2m-jwks.json` |
| SPIFFE workload | `spiffe://authsec.demo/workload/release-reporter` |
| SPIFFE Client ID | `4671a9f4-a415-4f84-8e09-e9cc689ed7f8` |
| XAA Agent | `agent-repo-assistant` |
| XAA Agent Client ID | `397ad939-8e63-4eca-b8b4-4dcbe128e2b5` |
| GitHub App ID | `4357796` |
| GitHub installation ID | `148085763` |
| Model | `openai:gpt-5.4-mini` |

The introspection secret, Agent secret, OpenAI key, GitHub PEM, presenter session, raw tokens,
and M2M private key remain private in `.env`, `.state/`, or `.secrets/`. Never duplicate
them into documentation.

## Normal start

Terminal A:

```bash
cd /Users/pc/Desktop/authsec-demo
pnpm share
```

This one foreground supervisor owns:

- local MCP origin on port `8091`;
- `mcp-demo.mcpauthz.com` Cloudflare connector;
- local SPIRE Server, Agent, and OIDC Discovery Provider;
- `spire-demo.mcpauthz.com` Cloudflare connector.

Wait for:

```text
AuthSec demo is ready.
```

Terminal B:

```bash
cd /Users/pc/Desktop/authsec-demo
uv run preflight
```

Every row should pass. The public MCP origin returning `401` is correct: it proves the
protected endpoint is reachable and challenges unauthenticated callers.

## Normal stop and restart

Preferred stop: press `Ctrl-C` in Terminal A.

If the foreground terminal was lost:

```bash
cd /Users/pc/Desktop/authsec-demo
pnpm share:stop
```

Clean restart:

```bash
cd /Users/pc/Desktop/authsec-demo
pnpm share:stop
pnpm share
```

Do not manually launch loose `uvicorn` or `cloudflared` processes. `pnpm share` owns their
lifecycle and tears the complete group down if one child fails.

## Verify each completed flow

Keep `pnpm share` running before these commands.

### M2M Service Account

Deterministic, no LLM cost:

```bash
uv run demo-agent token ci-reporter
uv run demo-agent proof ci-reporter
```

Complete live run (identity proof + deny/allow proof + actual ReAct action):

```bash
uv run demo-agent run ci-reporter
```

Expected:

- the terminal names the exact local private-key path, file mode, RSA algorithm, `kid`,
  Client ID, and public JWKS URI without printing the private PEM;
- the signed assertion trace shows `iss`, `sub`, `aud`, `jti`, `iat`, `exp`, and the
  five-minute lifetime, followed by AuthSec's successful signature/audience/replay checks;
- the received access token is shown as its real header/payload plus a SHA-256 fingerprint,
  with only the bearer-enabling signature redacted, followed by the decoded claims;
- AuthSec `/oauth/token` returns 200;
- final token has `tf=m2m`, MCP `aud`, Reader scopes, Service Account `sub`, no `act`;
- visible tools are exactly `list_commits` and `get_readme`;
- the allowed `list_commits` GitHub action is shown before the deliberate denied write;
- a forced `create_issue` shows `DENY`, the AuthSec reason, and
  `github_action_executed=False` even though MCP correctly uses HTTP 200;
- a real `list_commits` call shows `ALLOW` and a GitHub commit URL;
- the ReAct model visibly selects `list_commits`, receives the MCP result, and produces its
  answer from that result.

### SPIFFE workload

`pnpm share` must still be running in Terminal A. It owns the SPIRE Server, SPIRE Agent,
OIDC issuer, MCP server, and both tunnels. `pnpm share:stop` stops all of them; the workload
commands now detect that state and tell you to restart `pnpm share` instead of emitting an
SVID SDK traceback.

Deterministic proof:

```bash
pnpm agent:spiffe:proof
```

Complete live run (SVID exchange + deny/allow proof + actual ReAct action):

```bash
pnpm agent:spiffe
```

Expected:

- the seven-stage trace shows the local SPIRE Agent socket, registered SPIFFE ID, actual
  JWT-SVID `sub`, exact AuthSec token-endpoint `aud`, five-minute SVID lifetime, and the
  redacted assertion sent to `POST /oauth/token`;
- no AuthSec client secret or GitHub credential is present in the workload container;
- `spiffe_id_matches_registration=True` and AuthSec issues a separate resource-bound token;
- `create_issue` is absent from ReAct discovery and a forced call prints the full AuthSec
  denial before the GitHub provider;
- an allowed GitHub read returns commit evidence;
- the workload ReAct agent selects `list_commits`, performs the MCP action, and renders the
  real result.

### XAA delegated Agent

If the presenter's local browser session is missing or expired:

```bash
uv run demo-agent login
```

Authenticate with the named demo account you want to appear as the human `sub`. It may be
your presenter/admin account. The OAuth login creates/reuses the human user record; there is
no admin-console Create User button for this flow.

For the write-capable pitch, give that human **Triage** (or an equivalent Application role
containing `github_mcp_demo:issues:write`) on **GitHub MCP Demo**. Workspace-admin status by
itself is not the evidence: the effective Application relationship is what determines the
Agent's MCP capabilities.

Verify token acquisition:

```bash
uv run demo-agent token repo-assistant
```

Expected: the final delegated token preserves the human `sub`,
`act.client_id=agent-repo-assistant`, and `tf=xaa`.

If you deliberately want to show first-contact gating, first remove the human's Application
role. The token command then returns `access_pending` and a request ID with no MCP or GitHub
call. In AuthSec open:

```text
GitHub MCP Demo → Connections → Requests
```

Confirm the signed-in human is the subject, `agent-repo-assistant` is the actor, and GitHub
MCP Demo is the target. Approve with **Triage**. For the shorter pitch, pre-stage this
relationship instead of showing the pending step.

Run the actual delegated Agent:

```bash
uv run demo-agent run repo-assistant --interactive
```

Expected final claims:

- `sub=<signed-in human UUID>`;
- `act.client_id=397ad939-8e63-4eca-b8b4-4dcbe128e2b5`;
- `tf=xaa`;
- `aud=https://mcp-demo.mcpauthz.com/mcp`;
- effective Application access includes the sandbox issue action;
- ReAct first selects a read tool, then selects `create_issue`;
- the MCP result is labeled **ALLOWED** and returns the actual GitHub issue URL from
  `Aditya250401/authsec-demo-sandbox`.

### Claude Code

The connection command is needed only once per Claude Code configuration:

```bash
claude mcp add --transport http --scope local github-mcp \
  https://mcp-demo.mcpauthz.com/mcp
```

Inspect it:

```bash
claude mcp list
```

Complete OAuth as the Reader user. Ask Claude Code:

```text
Use github-mcp to summarize the five latest commits in github-mcp-server.
```

Reader must see the two read tools and must not see `create_issue`.

### Codex

The connection commands are needed only once per Codex configuration:

```bash
codex mcp add github-mcp --url https://mcp-demo.mcpauthz.com/mcp
codex mcp login github-mcp \
  --scopes github_mcp_demo:commits:read,github_mcp_demo:repo:read
codex mcp get github-mcp --json
```

Claude Code and Codex have independent OAuth client registrations and bearers. Never copy a
bearer from one client into the other.

## Complete smoke and rehearsal commands

Public and M2M checks, with XAA skipped:

```bash
uv run smoke
```

Assert first-contact pending XAA:

```bash
uv run smoke --expect-xaa pending
```

After Triage approval, explicitly allow one sandbox write:

```bash
uv run smoke --expect-xaa approved --allow-write
```

Live revocation drill:

```bash
uv run smoke --expect-xaa approved --revocation-drill
```

The revocation command pauses while you revoke the Connection, then retries with the same
unexpired token and expects an AuthSec denial.

## Rehearsal cleanup

`reset` is optional and requires a short-lived workspace-admin bearer because it revokes
recorded JTIs and the Agent Connection through admin APIs. Do not store that bearer in
`.env`.

```bash
cd /Users/pc/Desktop/authsec-demo
export AUTHSEC_ADMIN_TOKEN='<short-lived workspace-admin bearer>'
uv run reset "$DEMO_RUN_ID"
unset AUTHSEC_ADMIN_TOKEN
```

Reset is intentionally constrained to:

- workspace `41c3ab74-3393-4a2f-abd2-4245fcd8f690`;
- Application `GitHub MCP Demo` and its exact Resource URI;
- recorded JTIs from this run;
- the `agent-repo-assistant` Connection;
- issues carrying the exact run marker in `Aditya250401/authsec-demo-sandbox`.

It does not delete the Application, users, roles, scopes, service accounts, GitHub App, or
read repositories.

## Rebuild setup from scratch

The following sections are recovery/reference. They are not required for normal startup on
this machine.

### Preferred recovery after an AuthSec database reset

Use the one-token reconciler before following the manual sections below:

```bash
cd /Users/pc/Desktop/authsec-demo
pnpm recover
```

Paste a short-lived AuthSec workspace **owner/admin OAuth bearer** into the hidden prompt.
The command never stores that bearer. It reconstructs the Application, introspection
credential, scopes, roles, tool mappings, M2M Service Account, external SPIRE provider,
SPIFFE workload, confidential Agent, presenter Triage assignment, and activation state. It
temporarily starts `pnpm share`, runs deterministic M2M/SPIFFE proofs, and stops everything
before returning.

For a read-only comparison first:

```bash
pnpm recover --audit
```

The GitHub App/PEM, Cloudflare tunnels, M2M private key, and local SPIRE Server state are
preserved as durable user-owned trust anchors. A recovery run never deletes or replaces
them. After recovery, repeat only the user-owned OAuth ceremonies that an administrator
must not impersonate:

```bash
uv run demo-agent login
```

Claude Code and Codex will likewise request their independent OAuth logins on first use.
See `recovery.md` for the design, failure model, and non-interactive stdin option.

### 1. Install local dependencies

Requirements:

- Python 3.12;
- `uv`;
- `pnpm` 9.x;
- Docker Desktop;
- `cloudflared`;
- Claude Code/Codex only if showing those clients.

```bash
cd /Users/pc/Desktop/authsec-demo
uv sync --extra dev
pnpm install
test -f .env || cp .env.example .env
```

The project consumes the checked-out AuthSec Python SDK at:

```text
/Users/pc/Desktop/authnull/sdk-authsec/packages/python-sdk
```

### 2. Prepare personal GitHub resources

Exactly three repositories are used:

```text
Aditya250401/sdk-authsec
Aditya250401/github-mcp-server
Aditya250401/authsec-demo-sandbox
```

The sandbox must have Issues enabled. The server never accepts a repository argument for
write operations; `create_issue` is hard-pinned to the sandbox.

Create one personal GitHub App named `AuthSec Personal MCP Demo`:

| GitHub App field | Value |
|---|---|
| Homepage | `https://mcp-demo.mcpauthz.com` |
| Callback URLs | none |
| Request user authorization | off |
| Device Flow | off |
| Webhooks | off |
| Contents permission | Read-only |
| Issues permission | Read and write |
| Metadata | GitHub-required Read-only |
| All other permissions | No access |
| Installation scope | Only this personal account |

Generate one private PEM and install the App on exactly the three repositories. Record the
App ID, Installation ID from `/settings/installations/<id>`, and PEM path in `.env`.

The GitHub App permission can write issues on all selected repositories, but the server's
tool contract permits issue creation only in the sandbox. AuthSec independently decides
whether the caller may invoke the write tool.

### 3. Create the AuthSec Application

In workspace `41c3ab74-3393-4a2f-abd2-4245fcd8f690`, create:

| Field | Value |
|---|---|
| Name | `GitHub MCP Demo` |
| Type | `MCP Server` |
| Public base URL | `https://mcp-demo.mcpauthz.com` |
| Protected path | `/mcp` |
| Resource URI | `https://mcp-demo.mcpauthz.com/mcp` |

Create the exact canonical scopes:

```text
github_mcp_demo:commits:read
github_mcp_demo:repo:read
github_mcp_demo:issues:write
```

Capture the Application UUID and one-time introspection secret in `.env`. The Application
UUID is normally also the introspection Client ID.

The MCP server does not need an owner email or admin token. An admin token is used only by
optional `bootstrap` and `reset` automation.

### 4. Publish and map the real tools

Start the server:

```bash
pnpm share
```

The SDK publishes the actual FastMCP manifest. In **GitHub MCP Demo → Tools**, configure:

| Actual tool | Canonical AuthSec scope |
|---|---|
| `list_commits` | `github_mcp_demo:commits:read` |
| `get_readme` | `github_mcp_demo:repo:read` |
| `create_issue` | `github_mcp_demo:issues:write` |

Create:

- **Reader**: commit-read + repo-read;
- **Triage**: both Reader scopes + issue-write.

Review and activate the Application. Tool manifest suggestions do not grant permission;
the AuthSec admin mappings and role grants are runtime policy.

### 5. Recreate the M2M Service Account

Generate or reuse local key material:

```bash
pnpm m2m:setup
```

Files:

```text
.secrets/svc-github-ci-private.pem    private, mode 0600
.state/m2m-jwks.json                 public JWK only
```

Keep `pnpm share` running so AuthSec can fetch:

```text
https://mcp-demo.mcpauthz.com/.well-known/m2m-jwks.json
```

In AuthSec:

```text
GitHub MCP Demo → Access → Add access → Machine credential (secret/key)
```

Use:

| Field | Value |
|---|---|
| Caller | `svc-github-ci` |
| Role | Reader |
| Credential type | Private key JWT |
| JWKS URI | `https://mcp-demo.mcpauthz.com/.well-known/m2m-jwks.json` |

After creation, open **Service Accounts → svc-github-ci** and copy the non-secret Client ID
once into `.env` as `AUTHSEC_M2M_CLIENT_ID`. Also keep the local key path and key ID in
`.env`. The M2M Client ID must not equal `AUTHSEC_AGENT_CLIENT_ID`.

### 6. Recreate direct user access

Join/invite the Reader user through the normal AuthSec login/membership path and bind
Reader on GitHub MCP Demo. Complete separate OAuth logins in Claude Code and Codex.

### 7. Recreate the confidential Agent and presenter session

In the same workspace, create Agent `agent-repo-assistant` with redirect URI:

```text
http://localhost:8126/callback
```

Store its Client ID and one-time secret in `.env`. Do not use this Client ID for M2M.

Run `uv run demo-agent login` as the named human you want to present. The login/registration
flow creates or reuses that user record. For the default write-capable pitch, grant Triage
on GitHub MCP Demo and pre-stage the Connection. To demonstrate `access_pending` instead,
temporarily remove the Application role and approve the resulting request with Triage.

### 8. Recreate local SPIRE federation

Create the external tunnel once:

```bash
cloudflared tunnel create authsec-spire-demo
cloudflared tunnel route dns authsec-spire-demo spire-demo.mcpauthz.com
```

Copy `spire/cloudflared-config.yml.example` to:

```text
/Users/pc/.cloudflared/authsec-spire-demo.yml
```

Insert the tunnel UUID and credentials path. Start `pnpm share`, then in AuthSec choose:

```text
GitHub MCP Demo
→ Access
→ Add access
→ Kubernetes workload, no secret
→ Bring your own SPIRE
```

Use:

| Field | Value |
|---|---|
| Provider | `AuthSec Demo Local SPIRE` |
| Issuer | `https://spire-demo.mcpauthz.com` |
| Trust domain | `authsec.demo` |
| Workload | `wl-release-reporter` |
| External SPIFFE ID | `spiffe://authsec.demo/workload/release-reporter` |
| Role | Reader/Readonly with the two read scopes |

Do not select AuthSec-managed SPIRE: it produces an `authsec.local` identity that does not
match this demo's local `authsec.demo` trust domain. Store the returned non-secret OAuth
Client ID in `.env` as `SPIFFE_CLIENT_ID`.

## Environment contract

`.env` is mode `0600` and git-ignored. `.env.example` contains names/defaults only.

| Group | Required variables | Notes |
|---|---|---|
| Authorization server | `AUTHSEC_ISSUER`, `AUTHSEC_AUTHORIZATION_SERVER`, `AUTHSEC_JWKS_URL`, `AUTHSEC_INTROSPECTION_URL` | Pinned to `https://app.authsec.ai` endpoints |
| Protected resource | `AUTHSEC_RESOURCE_URI`, `AUTHSEC_RESOURCE_NAME`, `AUTHSEC_RESOURCE_SERVER_ID` | URI must end in `/mcp` |
| Resource credential | `AUTHSEC_INTROSPECTION_CLIENT_ID`, `AUTHSEC_INTROSPECTION_CLIENT_SECRET` | Server-side only |
| Runtime policy | `AUTHSEC_POLICY_MODE`, `AUTHSEC_VALIDATION_MODE`, `AUTHSEC_PUBLISH_MANIFEST` | Must be `remote_required`, `jwt_and_introspect`, `true` |
| GitHub provider | `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, `GITHUB_PRIVATE_KEY` | Server-side only |
| M2M | `AUTHSEC_M2M_CLIENT_ID`, `AUTHSEC_M2M_PRIVATE_KEY_PATH`, `AUTHSEC_M2M_KEY_ID` | Private key belongs to caller, not MCP origin |
| SPIFFE | `SPIRE_TRUST_DOMAIN`, `SPIRE_OIDC_DISCOVERY_URL`, `SPIRE_TUNNEL_CONFIG`, `SPIRE_AGENT_SOCKET_PATH`, `SPIFFE_ID`, `SPIFFE_CLIENT_ID` | No OAuth client secret |
| XAA | `AUTHSEC_AGENT_CLIENT_ID`, `AUTHSEC_AGENT_CLIENT_SECRET`, `AUTHSEC_AGENT_LOGIN_PORT` | Confidential Agent, separate from M2M |
| Model | `DEMO_LLM_MODEL`, `OPENAI_API_KEY` | Tool-capable model |
| Operations | `AUTHSEC_DEMO_WORKSPACE_ID`, `DEMO_RUN_ID`, `MCP_TUNNEL_CONFIG`, `DEMO_PORT` | Workspace guard and process routing |

Do not put `AUTHSEC_ADMIN_TOKEN` in `.env`.

## Recovery

| Symptom | Meaning | Action |
|---|---|---|
| Cloudflare `530` | DNS exists; local connector/origin is stopped | `pnpm share:stop`, then `pnpm share` |
| Port `8091` occupied | another or stale origin exists | use `pnpm share:stop`; do not start a second group |
| `Unknown MCP server` plus `530` | protected-resource metadata could not be reached | keep `pnpm share` running and retry |
| `client does not support private_key_jwt` | XAA Agent ID or secret-auth client used as M2M | use the distinct `svc-github-ci` Client ID |
| Other `invalid_client` | client, `kid`, JWKS, assertion audience, or credential state mismatch | verify Service Account and public JWKS |
| every tool denied | mappings absent/stale or Application not active | verify all three admin mappings and activation |
| `create_issue` appears for Reader | role or mapping is over-privileged | stop demo and correct Reader/tool policy |
| GitHub 403/404 | App permission or selected repository mismatch | inspect personal App installation and three target repos |
| Wrong human appears in XAA | browser reused another signed-in session | use a private/separate profile and repeat login |
| XAA stays pending | wrong request/role or stale process | confirm human + Agent + target, approve Triage, rerun fresh command |
| `The SPIFFE demo infrastructure is not ready` | `pnpm share` is stopped | start `pnpm share` in Terminal A, wait for ready, keep it running |
| SPIRE Agent reports `certificate signed by unknown authority` after a long shutdown | cached demo Agent SVID predates the Server's current bundle | `pnpm share` now clears only the recoverable Agent cache/socket and re-attests once; Server CA/JWT state is preserved |
| SPIFFE SVID fetch fails after the readiness gate | Agent socket/attestation changed during the run | inspect Compose and SPIRE Agent logs |
| SPIFFE issuer/JWKS returns transient 502/503/504 | tunnel edge briefly could not reach OIDC; identity was not rejected | the Agent retries four total exchanges with fresh SVIDs; if exhausted, restart `pnpm share` and check discovery plus `/keys` |
| workload waits to attest | AuthSec-managed path was selected | recreate using Bring your own SPIRE |
| M2M Logs empty after successful token 200 | logging ingestion/UI gap | use terminal claims, Service Account activity, and Audit Logs as evidence |

Diagnostics:

```bash
docker compose -f spire/docker-compose.spire.yml ps
docker compose -f spire/docker-compose.spire.yml logs --tail=100 \
  spire-server spire-agent spire-oidc
curl -fsS https://mcp-demo.mcpauthz.com/healthz
curl -fsS https://mcp-demo.mcpauthz.com/.well-known/oauth-protected-resource/mcp | jq
curl -fsS https://spire-demo.mcpauthz.com/.well-known/openid-configuration | jq
curl -fsS https://spire-demo.mcpauthz.com/keys | jq '.keys | length'
```

## Safety rules

- Never display `.env`, `.secrets/`, `.state/alice-session.json`, raw JWTs, or PEM files.
- Never send the AuthSec user/Agent bearer to GitHub. GitHub credentials remain server-side.
- Never send the GitHub App installation token to AuthSec or an agent.
- Never write to `sdk-authsec` or `github-mcp-server`; only the sandbox is writable.
- Never describe a tool's suggested scope as an actual permission.
- Never bypass reset workspace/resource guards.
- Always stop the full share group after a task or rehearsal.
