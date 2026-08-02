# AuthSec demo — agent instructions

Read `implementation.md` before changing code, `setup.md` before operating or
provisioning the demo, and `pitch.md` before changing the live narrative.

## Long-running process lifecycle

- `pnpm share` owns the MCP origin, MCP Cloudflare connector, optional SPIRE
  connector, and local SPIRE Compose stack as one foreground process group.
- Before handing a task back, stop every long-running process started for that
  task and verify the origin port and project containers are no longer active.
- Keep the share group running only when the user explicitly asks for the demo
  to remain live.
- Prefer `Ctrl-C` in the foreground terminal. If that terminal is unavailable,
  use `pnpm share:stop`. Never use broad kill commands that may affect unrelated
  services.
- A final process check should cover port `8091`, both demo Cloudflare config
  paths, the `authsec-demo-server` process, and
  `spire/docker-compose.spire.yml`.
