# AuthSec demo pitch

## The story in one sentence

**AI does not introduce one new kind of identity. It introduces several ways of acting — as a person, as a machine, as a workload, or on behalf of someone — and AuthSec manages all four through one control plane.**

This is the main demo narrative. Keep the detailed policy configuration, scope mapping,
token revocation, and failure testing for technical follow-up rather than the live pitch.

---

## The idea the audience should remember

Most identity systems were designed around two assumptions:

1. a human signs in; or
2. a backend receives a credential.

AI systems break that simple split. The same AI capability may be used interactively by a
person, run autonomously in CI, execute inside Kubernetes, or act on behalf of a named user.
Those are not merely four login methods. They are four different **identity and trust
paradigms**.

AuthSec is AI-native because these paradigms are first-class parts of the product. An
application does not need four unrelated authentication systems, and an agent does not
need to be disguised as a user or reduced to a generic API key.

## The four identity paradigms

| Identity paradigm | Who is acting? | How trust is established | Simple example |
|---|---|---|---|
| **Human identity** | A person using an AI client | Interactive OAuth/OIDC login | The presenter asks Claude Code to inspect a repository |
| **Machine identity** | An autonomous service or scheduled agent | Service account proving possession of its private key | A CI reporter summarizes recent commits |
| **Workload identity** | The running software instance itself | SPIFFE/SPIRE attests where and how the workload is running | A Kubernetes agent receives a short-lived runtime identity |
| **Delegated agent identity** | An agent acting for a person | AuthSec preserves both the human subject and the agent actor | A repository assistant acts for a named user without becoming that user |

The distinction matters:

- A **human identity** answers, “Which person is here?”
- A **machine identity** answers, “Which autonomous service is calling?”
- A **workload identity** answers, “Which verified runtime is executing this code?”
- A **delegated identity** answers, “Which agent is acting, and for which person?”

All four can reach the same protected Application. AuthSec gives the Application one place
to understand and manage those relationships.

---

## 30-second opening — say this verbatim

> AI does not create one new identity type. It creates multiple ways of acting. An AI can
> be used directly by a person, run autonomously as a service, execute as an attested
> workload, or act on behalf of a customer. Most systems force all of those into either a
> human login or an API key. AuthSec treats each one as a first-class identity and brings
> them together around the Application being protected. Let me show you the same MCP
> application being accessed through four different trust models, all managed from one
> control plane.

## What to have open before the pitch

Keep the number of screens small. Pre-open these views so the demo feels like one coherent
product rather than a tour of configuration pages.

1. **AuthSec → GitHub MCP Demo → Overview** — the home screen and visual anchor.
2. **Claude Code** connected to `https://mcp-demo.mcpauthz.com/mcp` — the human experience.
3. **AuthSec → Service Accounts → `svc-github-ci`** — the machine identity.
4. **AuthSec workload detail → `wf-release-reporter`** — the SPIFFE workload identity.
5. **AuthSec → Agents → `agent-repo-assistant`** — the delegated agent.
6. A terminal in `/Users/pc/Desktop/authsec-demo` for the two short runtime commands.

Do not open the `.env` file, private keys, raw credentials, the detailed scope matrix, or
token-revocation screens during the main pitch.

Start the platform before the audience arrives:

```bash
cd /Users/pc/Desktop/authsec-demo
pnpm share
```

Use another terminal for agent commands.

---

## The live pitch — 8 to 10 minutes

### 1. Start with the Application, not the protocol — 60 seconds

**Screen:** `GitHub MCP Demo → Overview`

Say:

> This is the protected Application. It happens to be an MCP server backed by GitHub, but
> the important point is that the Application is the center of the model. Around it are
> people, autonomous services, runtime workloads, and delegated agents. AuthSec gives the
> Application one control plane for all of them.

Point only to the Application name and Resource URI. Do not enter the Tools or Scopes tabs.

Key message:

> The application integrates with AuthSec once. It does not build a separate identity
> system for every kind of AI caller.

### 2. Paradigm one: a person using an AI client — 90 seconds

**Screen:** Claude Code

Ask Claude Code to perform a harmless read operation through the MCP server, for example:

```text
Use the GitHub MCP demo to summarize the latest commits in my demo repository.
```

Say:

> In this mode, the AI is part of a human session. A named person is present and has authenticated
> interactively. The AI client can change — Claude Code, Codex, or another MCP client — but
> the protected Application receives an AuthSec-issued identity instead of accepting a
> permanent GitHub token from the client.

What the audience should notice:

- The experience feels like normal AI-assisted work.
- The person remains the principal.
- The MCP client is not the source of authorization truth.

Transition:

> But many agents do not have a person sitting in front of them.

### 3. Paradigm two: an autonomous machine — 90 seconds

**Screen:** `Service Accounts → svc-github-ci`

Then run:

```bash
uv run demo-agent run ci-reporter
```

Say:

> This is an autonomous machine identity. There is no browser session and no human token.
> The CI reporter proves possession of its own private key, receives a short-lived token,
> and calls the same MCP Application. Its identity is stable and accountable without
> pretending to be an employee.

Point to the service-account name, owner, authentication method, Application relationship,
and last activity if the screen exposes them.

In the terminal, point briefly to the two outcome panels: the attempted write is denied
before GitHub, while the allowed read returns a real commit. Then show the ReAct model
selecting `list_commits`. Do not explain the scope matrix unless asked.

Key message:

> A background agent should be represented as a machine, not as a shared user account.

Transition:

> Sometimes even a machine credential is more than we want to distribute.

### 4. Paradigm three: identity from the runtime — 90 seconds

**Screen:** `wf-release-reporter` workload detail

If a live run is stable, execute:

```bash
pnpm agent:spiffe
```

If the runtime is already staged, use the workload screen and its latest activity instead
of rerunning Docker during the pitch.

Say:

> Here, the agent does not carry a long-lived OAuth client secret. SPIRE attests the
> workload and gives it a short-lived SPIFFE identity. AuthSec accepts that runtime proof
> and turns it into access to the same Application. The trust comes from the workload's
> verified execution environment, not from a secret copied into a configuration file.

Point to the workload name, SPIFFE ID, attestation state, and last activity. Avoid walking
through cluster selectors or installation commands unless the audience asks.

In the terminal, point to `svid_claims.sub`, the AuthSec token-endpoint audience,
`spiffe_id_matches_registration=True`, and the actual model-selected `list_commits` result.
The red/green outcome panels make the capability boundary visible without opening policy
configuration.

Key message:

> The identity follows the verified workload, not a credential file.

Transition:

> The most important AI case is when an agent is neither an independent machine nor the
> human themselves — it is acting for someone.

### 5. Paradigm four: an agent acting for a person — 2 minutes

**Screen:** `Agents → agent-repo-assistant`

Run the already staged flow:

```bash
uv run demo-agent run repo-assistant --interactive
```

Say:

> This agent is acting for the signed-in presenter, but it does not become that person.
> AuthSec preserves two identities: the human is the subject, and `agent-repo-assistant` is
> the actor. That distinction
> is fundamental for AI governance because we can answer both “whose authority was used?”
> and “which agent actually performed the action?”

Point first to the human subject and Agent actor fields. Then show the ReAct model reading
repository context, selecting `create_issue`, and receiving the real sandbox GitHub issue
URL. This is the higher-capability delegated action; do not decode the entire token.

Key message:

> Delegation preserves the human-agent relationship instead of collapsing both into one
> bearer credential.

### 6. Return to the Application — 60 seconds

**Screen:** `GitHub MCP Demo → Overview`

Say:

> We have now reached one Application through four different identity paradigms: a person,
> an autonomous machine, an attested workload, and an agent acting for a person. Each used
> the trust proof appropriate to how it operates. AuthSec brought them into one control
> plane, so the Application has one integration and the organization has one place to see
> who — or what — is acting.

Summarize with four verbs:

> **Recognize the identity. Verify the right proof. Preserve the context. Govern the
> Application.**

---

## Why this is AI-native

“AI-native” should not sound like a branding adjective. Tie it to concrete product design:

1. **Identity plurality is built in.** Humans, services, workloads, and delegated agents
   are separate first-class principals.
2. **Agents preserve dual identity.** AuthSec can retain the human subject and agent actor
   instead of losing one side of the relationship.
3. **The Application is the convergence point.** Different callers and trust proofs arrive
   at one protected resource model.
4. **Trust is appropriate to the runtime.** Interactive login, private-key proof, and
   workload attestation are used where each makes sense.
5. **The implementation is standards-oriented.** OAuth/OIDC, RFC 7523 private-key JWT,
   SPIFFE/SPIRE, and token exchange provide interoperable foundations rather than a closed
   agent credential format.

## How to position AuthSec against adjacent products

Avoid saying that every other vendor lacks these features. The stronger and more defensible
claim is that AuthSec makes their convergence the primary product model.

| Adjacent category | What it is typically optimized for | The AI identity gap AuthSec addresses |
|---|---|---|
| **Workforce/consumer identity** | Human login and user sessions | Autonomous services and agent delegation are often represented indirectly |
| **API gateway** | Authenticating and routing API requests | It may validate a token without modeling the full human, agent, machine, and workload relationship |
| **Secrets manager** | Storing and distributing credentials | A securely stored secret is still a credential; it is not a workload identity or delegation model |
| **Point OAuth integration** | Protecting one client-to-resource flow | Each new AI operating mode can become another custom integration |
| **AuthSec** | Identity and authorization for AI-facing Applications | Four identity paradigms converge on one Application control plane |

Use this line:

> AuthSec is not trying to replace every identity provider, gateway, or secrets manager. It
> is the identity and authorization layer that makes their signals usable for AI agents and
> MCP Applications.

---

## The technical foundation — one slide, not the story

If the audience is technical, show this mapping briefly after explaining the four
paradigms. Protocol names validate the architecture; they should not lead the presentation.

| Paradigm | Technical foundation |
|---|---|
| Human identity | OAuth 2.1 / OpenID Connect |
| Machine identity | Client credentials with RFC 7523 private-key JWT |
| Workload identity | SPIFFE JWT-SVID issued by SPIRE |
| Delegated agent identity | OAuth token exchange (RFC 8693) and AuthSec's ID-JAG profile |

Say:

> The product experience is unified, but the trust proof is not artificially made the
> same. AuthSec uses the standard that fits each identity paradigm.

Technical accuracy notes:

- ID-JAG is an active Internet-Draft/profile, not a finalized RFC.
- The delegated flow is cross-Application; it does not require two separate workspaces.
- “Secretless workload” means the workload does not receive a long-lived OAuth client
  secret. It does not mean every supporting system contains no secrets.

---

## 30-second close — say this verbatim

> The future is not one agent identity. AI will act as people, machines, workloads, and
> delegates — often against the same Application. If we reduce all of that to API keys, we
> lose who is acting, why they are trusted, and on whose behalf they operate. AuthSec gives
> every AI actor the identity model that fits it, while giving the Application one control
> plane. Whatever form an agent takes, AuthSec can recognize it, verify it, and preserve the
> context that makes its actions accountable.

End with this question:

> Which of these four identity paradigms are your AI agents being forced to pretend they
> are today?

---

## What belongs in Q&A, not in the main pitch

The implementation supports deeper demonstrations, but do not make them the headline:

- exact scope vocabulary and tool-to-policy mappings;
- denied tool calls and fail-closed behavior;
- token introspection and revocation;
- raw JWT claims;
- GitHub App installation permissions;
- SPIRE registration commands;
- bootstrap and cleanup mechanics.

Use [implementation.md](/Users/pc/Desktop/authsec-demo/implementation.md) for code-level
questions and [setup.md](/Users/pc/Desktop/authsec-demo/setup.md) for operational questions.
