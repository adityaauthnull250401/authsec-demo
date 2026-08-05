# Running the demo in Kubernetes so AuthSec discovery detects it

This directory deploys the demo's MCP server and its two agent runtimes into a
cluster. The point is not just to run them — it is for the **AuthSec discovery
collector** to find them and report them as governed agent candidates.

Deploying these workloads and installing the collector are independent. Either
can happen first; the collector picks up new workloads in real time and, if
resync is enabled, already-running ones too.

---

## 1. How the collector decides something is an agent

Worth understanding before you edit the manifests, because it determines which
fields you can safely change.

The collector runs as a **validating admission webhook**. When any workload is
created, the API server hands it the object and it inspects the **pod spec**:

| signal | what it reads | confidence |
|---|---|---|
| label `authsec.io/agent` | pod template labels | **high** |
| image reference contains a known framework token | `image` | **high** |
| env var **key** is a framework marker (`ANTHROPIC_API_KEY`, `LANGCHAIN_*`, …) | key only | **high** |
| `command`/`args` contain a framework token | `command`, `args` | medium |
| mounts an MCP config (`/etc/mcp`, `mcp.json`, …) | volume mounts | medium |
| env key is a bare provider credential (`OPENAI_API_KEY`, `GEMINI_API_KEY`, …) | key only | low |

Two consequences that matter:

- **It reads the spec, never the running process.** It does not exec into the
  container, watch syscalls, or inspect traffic. If the manifest does not say
  "agent" in one of the ways above, the workload is invisible — no matter what it
  actually does at runtime.
- **Env var values are never read for credentials.** Only key *names* drive
  detection. `OPENAI_API_KEY` from a `secretKeyRef` is recorded as a
  `secret_ref` (Secret name, key, env var) so provisioning knows which
  credential to broker later — the value never leaves the cluster.

Detection is **per container**, not per pod. Two agent-shaped containers in one
pod produce two separate governed agents.

### Why these manifests carry redundant signals

`demo-agents.yaml` sets the `authsec.io/agent` label **and** names `langchain` in
the args **and** passes `OPENAI_API_KEY`. That is deliberate: any one of them is
sufficient, so detection does not silently break if someone rewrites the
entrypoint or moves a credential.

If you strip signals, **keep the label**. It is the only one that does not depend
on guessing from an image name or an environment variable.

---

## 2. Build an image

There is no application Dockerfile in this repo yet — the demo is normally run
locally via `pnpm`/`uv`. You will need one. Minimal shape:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY apps ./apps
RUN pip install --no-cache-dir .
EXPOSE 8091
CMD ["authsec-demo-server"]
```

```bash
docker build -t <registry>/authsec-demo:latest .
docker push  <registry>/authsec-demo:latest
```

If your cluster cannot pull from a registry, load the image directly (kind:
`kind load docker-image`, minikube: `minikube image load`) and set
`imagePullPolicy: Never`.

---

## 3. Fill in the placeholders

`demo-agents.yaml` has `REPLACE_ME` and `<...>` markers. You need:

| value | where it comes from |
|---|---|
| image reference | step 2 |
| `OPENAI_API_KEY` | your OpenAI account |
| GitHub App id, installation id, private key | `setup.md` — the demo's GitHub App |
| `AUTHSEC_RESOURCE_SERVER_ID` | the AuthSec console, after registering the MCP resource |
| `AUTHSEC_AGENT_CLIENT_ID` / secret | the AuthSec console, agent OAuth client |

The Secrets in this file are placeholders for readability. **Do not commit real
values.** Create them out of band instead:

```bash
kubectl create secret generic demo-llm-creds \
  -n authsec-demo --from-literal=openai="$OPENAI_API_KEY"

kubectl create secret generic demo-github-app \
  -n authsec-demo --from-file=private-key.pem=.secrets/svc-github-ci-private.pem

kubectl create secret generic demo-agent-oauth \
  -n authsec-demo --from-literal=client-secret="$AUTHSEC_AGENT_CLIENT_SECRET"
```

…then delete the three `kind: Secret` blocks from the YAML before applying.

---

## 4. Deploy

```bash
kubectl apply -f k8s/demo-agents.yaml
kubectl get pods -n authsec-demo
```

Three Deployments, each with its own ServiceAccount:

| workload | what it is | why a separate SA |
|---|---|---|
| `demo-mcp-server` | the protected FastMCP resource | it is the resource, not a caller |
| `demo-agent-runtime` | LangChain ReAct runtime | autonomous authority |
| `demo-xaa-agent` | acts on behalf of a signed-in human | delegated authority — must never share an identity with the above |

The ServiceAccount becomes `provisioning_hints.identity_anchor` in the sighting
(`system:serviceaccount:authsec-demo:demo-agent-runtime`), which is what a
governed OAuth client gets bound to. Sharing one SA across all three would make
them indistinguishable to governance, which defeats the point.

---

## 5. Install the collector

From the [discovery-agent](https://github.com/authsec-ai/discovery-agent) repo:

```bash
helm install discovery-agent ./charts/authsec-discovery-agent \
  --namespace authsec-system --create-namespace \
  --set cluster.name="<name-this-cluster>" \
  --set controlPlane.url=https://app.authsec.ai \
  --set controlPlane.sourceToken="<token>" \
  --set resync.enabled=true
```

Three flags decide whether this works:

- **`cluster.name` is required** and is part of the agent fingerprint. Two
  clusters running the same workload under the same name collapse into one
  governed agent. Use something stable and unique per cluster.
- **`resync.enabled=true`** — the default is `false`, and with it off the
  collector only sees workloads created *after* it installs. If you deploy the
  demo first, leave resync off and you will see nothing until pods restart.
- **`controlPlane.sourceToken`** — see the caveat below.

The chart defaults are deliberately safe and should not be changed:
`failurePolicy: Ignore`, `sideEffects: None`, `timeoutSeconds: 3`. The collector
always allows every request and can never block a deployment. Its RBAC is
`list`-only on workloads plus its own TLS Secret and webhook configuration.

---

## 6. Confirm it worked

```bash
kubectl logs -n authsec-system -l app.kubernetes.io/name=discovery-agent | grep "agent sighted"
```

You should see one line per agent container, then the same agents in the AuthSec
console under **IGA → Discovered Agents** with status `unregistered`, waiting to
be claimed or quarantined.

To preview what the collector finds *without* sending anything to the control
plane, add `--set dryRun=true`. Note the caveat below.

---

## Known caveats

**The source token.** `controlPlane.sourceToken` is documented as being revealed
when a discovery source is created in the console, but that enrollment endpoint
does not exist yet, and no token can currently be minted that satisfies the
`discovery:report` permission. Until that lands, the collector will detect
correctly and get `401 Unauthorized` when reporting. Check with the AuthSec team
before assuming the console will populate.

**`dryRun=true` does not suppress the resync channel.** It silences the admission
path only; resync still POSTs. If you enable both, sightings reach the control
plane despite the startup log saying otherwise.

**Agents the collector cannot see.** A workload with a generic image name, a
generic entrypoint, its framework installed at build time, and its provider
credential read from a *mounted file* rather than an env var trips **no signal**
and is never reported. This is inherent to inspecting manifests rather than
behaviour. Two workarounds:

```bash
# declare it explicitly
kubectl label deploy <name> authsec.io/agent=true

# or teach the collector your own image names
helm upgrade ... --set "detection.extraImageTokens=acme-copilot internal-rag"
```

**Expect false positives at `low` confidence.** `minConfidence` defaults to
`low`, so any container carrying `OPENAI_API_KEY` is reported — including a
nightly batch job that is not really an agent. That is the intended trade: a
false positive costs one *Ignore* click, a miss is an ungoverned agent. Raise it
with `--set detection.minConfidence=medium` if the inventory gets noisy.

**Namespace scope.** The collector skips `kube-system`, `kube-public`,
`istio-system` and its own namespace by default. To opt a namespace out later
without redeploying:

```bash
kubectl label namespace <ns> authsec.io/discovery=disabled
```

---

## Teardown

```bash
kubectl delete -f k8s/demo-agents.yaml
helm uninstall discovery-agent -n authsec-system
```

Uninstalling removes the `ValidatingWebhookConfiguration`, so the API server
stops calling the collector immediately. Already-reported agents stay in the
AuthSec inventory — the discovery source FK is `ON DELETE SET NULL`, so they
outlive the collector rather than disappearing with it.
