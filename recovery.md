# One-token recovery design

This is the recovery runbook for an AuthSec database reset or migration that invalidates
the demo's server-side records. Normal starts still use `pnpm share`; recovery uses
`pnpm recover`.

## Outcome

One short-lived AuthSec workspace **owner/admin OAuth bearer** is enough to reconstruct the
AuthSec-owned topology and prove the two unattended machine flows. The bearer is accepted
through a hidden terminal prompt and is never written to `.env`, `.state`, logs, or shell
history.

Recovery keeps the AuthSec UI origin separate from its API origin. `AUTHSEC_ISSUER` is the
OAuth issuer used for `/oauth/token`, while `AUTHSEC_ADMIN_API_URL` selects the product API
used to reconcile workspace records. Both production API settings default to
`https://prod.api.authsec.ai`; the browser console remains on `https://app.authsec.ai`.

```text
short-lived admin bearer
          │
          ▼
  inventory exact workspace
          │
          ├── Application + one-time introspection secret
          ├── canonical scopes + Reader/Triage roles
          ├── local-key-backed M2M Service Account
          ├── external SPIRE provider + exact SPIFFE workload
          ├── confidential XAA Agent + one-time secret
          └── token subject → Triage assignment (when it is a workspace user)
          │
          ▼
 temporary `pnpm share`
          │
          ├── publish real FastMCP manifest
          ├── apply exact admin tool mappings
          ├── activate after activation-preview passes
          ├── prove M2M allow/deny/read
          └── prove SPIFFE allow/deny/read
          │
          ▼
       clean stop
```

## What is durable and what is reconstructed

| Layer | Recovery treatment | Reason |
|---|---|---|
| GitHub App ID, installation and PEM | preserve and validate | External user-owned provider asset |
| Cloudflare tunnel configs and DNS | preserve and validate | External user-owned routing asset |
| M2M RSA private key | preserve; create only when both key files are absent | AuthSec stores only the public key and cannot recover the private key |
| Local SPIRE Server data | preserve | It owns the public issuer's CA/JWT signing continuity |
| AuthSec Application, roles, scopes, mappings | reconcile/create | Database-owned policy records |
| Introspection and Agent secrets | capture once into private `.env` | Returned once; required by the origin/XAA caller |
| M2M and SPIFFE OAuth Client IDs | rediscover/recreate and update `.env` | Non-secret database identifiers |
| Presenter browser session | recreate with `uv run demo-agent login` | An admin bearer cannot manufacture the user's interactive login ceremony |
| Claude/Codex OAuth sessions | recreate in each client | Each client owns its independent PKCE session and bearer |

## Safety model

- The command is additive/idempotent for the pinned Resource URI and canonical identities.
- It refuses ambiguous Applications, a wrong-URI same-name Application, an unexpected
  SPIFFE trust domain, incomplete local key state, or a conflicting M2M credential.
- It never deletes an Application, identity, provider, scope, role, or external asset.
- Unknown scopes are reported and preserved rather than silently deleted.
- One-time secrets are written atomically to mode-`0600` `.env` immediately after issue.
- `.state/recovery.json` is a resumable, non-secret checkpoint. It contains identifiers and
  phase names only.
- Failure does not attempt a cross-system rollback. Rerunning resumes from the durable
  checkpoint, which is safer than deleting records whose one-time credentials were issued.
- The managed share process is stopped in `finally`, including on verification failure.

## Commands

Audit the current database/local anchor relationship without mutation:

```bash
pnpm recover --audit
```

Rebuild and run deterministic proofs:

```bash
pnpm recover
```

The terminal asks for the OAuth bearer without echoing it. For non-interactive automation,
pass the token on standard input rather than a command-line argument:

```bash
printf '%s\n' "$AUTHSEC_ADMIN_TOKEN" | pnpm recover --token-stdin
```

`AUTHSEC_ADMIN_TOKEN` may also be exported for the process, but it is deliberately never
copied into `.env`.

If provider/API availability makes proof calls undesirable during configuration:

```bash
pnpm recover --skip-proofs
```

## Expected manual tail

The reconstruction can bind the OAuth token's user subject to Triage when that subject is a
user in the same workspace. It still cannot and should not synthesize interactive sessions.
After a database reset, complete these user-owned ceremonies once:

```bash
uv run demo-agent login
codex mcp login github-mcp \
  --scopes github_mcp_demo:commits:read,github_mcp_demo:repo:read
```

Claude Code likewise completes its own OAuth login on first use. This is not an automation
gap: replacing a user's login with an administrator token would erase the identity boundary
the demo is intended to prove.

## Database-change compatibility boundary

The recovery client uses `AUTHSEC_ADMIN_API_URL` and the product-level AuthSec APIs under
`/authsec/applications`, plus
workspace-scoped service-account, workload-provider, workload, and Agent endpoints. It does
not access the AuthSec database directly. If a migration changes physical tables while these
API contracts remain stable, recovery is unaffected. If an API contract changes, the command
fails at a named phase without losing the admin token or one-time credentials, and can resume
after the adapter is updated.
