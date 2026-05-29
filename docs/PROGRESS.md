# web-core extraction — progress & cutover playbook

Status as of the overnight autonomous run. Companion to
[web-core-extraction-plan.md](web-core-extraction-plan.md).

## Done (pushed to `main`)

Everything below is committed, tested (`go test ./...` green, race-tested where
concurrent), and pushed.

### `core/`

| Package | Notes |
|---------|-------|
| errors | AppError + typed constructors + WriteHTTPError JSON envelope |
| validation | validators + Validate/ValidateAll; **fixed a typed-nil panic still live in gearbox** |
| crypto | AES-256-GCM, HKDF+label (`New`), `NewFromHashedKey` gearbox-compat |
| migrate | golang-migrate runner over caller `fs.FS`; Up/Down/Steps/Version/Force |
| responses | ErrorResponse/SuccessResponse/ValidationResponse + WriteJSON |
| middleware | RateLimiter (x/time/rate); SecurityHeaders w/ Config-driven CSP (gearbox sanitizers kept, env reads removed) |
| events | generic pub/sub Hub (Topic filter, drop coalescing, WithBufferSize) |
| transport | SSE handler over events.Hub (topic param, keepalive, crypto/rand IDs) |
| auth | password policy + tokens + email; DB-backed session Manager; UserStore/AuthUser/AuditLogger interfaces; RequireAuth/RequireCSRF/RequirePasswordChange; dev loopback bypass (`-tags dev`) |
| webauthn | RP wrapper + webauthn.User adapter |

### `ui/`

- `ui.StaticFiles` embed (`//go:embed all:static`) + Makefile.
- `ui/components` (templ, pre-generated `_templ.go` committed): alerts, badge,
  toggle, modal, collapsible, icons, info_tooltip, doughnut, settings,
  metric_card, table, live_refresh, toast, and auth form fragments (login /
  change / forgot / reset). Render-to-buffer tests for all.
- `ui/static/js`: utils (toast, dom, formatting, char-limit), common
  (focus-trap, info-tooltip, page-header, keymap→`WebCoreKeymap`,
  datagrid→`.datagrid`, sse.js).
- `ui/static/css`: utilities + components (buttons, cards, modals,
  datagrid→`.datagrid`).
- `examples/gallery`: dev-only visual inspection server (chrome-verified).

## Deferred (not yet in web-core)

Intentionally left for the cutover, where the exact contract is observable:

- **Login HTTP handler builder** — meets app routing/rendering too intimately
  to design blind. The form *components* exist; wire the handler per app.
- **Password-reset email** — app concern. Call `Manager.RequestPasswordReset`,
  send the returned token yourself (no `EmailSender` in core).
- **Heavy/coupled JS**: `api.js` (baseURL+tenant), `header-search.js`,
  `shortcut-help.js`, `command-palette.js`, `charts/*`, and the **sidebar**
  (each app's nav differs). Abstract these during/after cutover.

## Decisions locked

- License **Elastic 2.0**; module `github.com/sarg3nt/web-core`; single repo;
  `ui/components` (not `ui/templ`, to avoid the a-h/templ import collision).
- Auth: **string** user IDs; **DB-backed session token** model; **RBAC stays
  app-side**; audit optional; dev-bypass env var + email configurable.
- Direct-to-`main` commits during build (branch protection bypassed as owner,
  per the user's explicit "c" choice). Cutover should still go via PR.

## Cutover playbook (Phases 6 & 7 — NOT started; needs the apps' full envs)

> [!IMPORTANT]
> Cutover mutates the live `gearbox` and `libation` repos and needs their full
> test/e2e suites (real `.env`, docker, etc.). Do this with the user present.

### Per-app mechanics

1. Branch the app (`feature/web-core-adopt-<pkg>`).
2. Add to the app `go.mod`:

   ```text
   require github.com/sarg3nt/web-core v0.0.0
   replace github.com/sarg3nt/web-core => ../web-core
   ```

3. Cut over **one package at a time**, smallest blast radius first:
   `errors → validation → crypto → migrate → responses → middleware/ratelimit →
   middleware/security_headers → events → transport → auth → webauthn → ui`.
4. For each: delete the now-duplicated file(s), repoint imports to
   `github.com/sarg3nt/web-core/...`, `go build ./... && go test ./...`
   (+ the app's e2e), commit.

### Auth cutover specifics

- Implement `auth.UserStore` + `auth.AuthUser` against the app's DB/model:
  - **gearbox**: UUID IDs map directly; wire its existing
    `GetUserByEmail`/`GetUserByID`/session-token/audit methods. Its RBAC
    (Component/Permission) stays app-side, layered over the authenticated user
    from `GetUserFromContext`. Re-add `RequireAdmin` app-side.
  - **libation**: stringify its int64 IDs at the store boundary
    (`strconv.FormatInt`/`ParseInt`); **add a `session_token` column** + the
    `SetSessionToken`/`ValidateSessionToken`/`ClearSessionToken` methods (it
    gains server-side session invalidation it lacked).
- gearbox `crypto`: construct with `crypto.NewFromHashedKey` initially so
  existing at-rest data still decrypts; migrate to labeled `New` later.
- gearbox `security_headers`: pass `d3js.org` via `Config.ExtraSources` (or a
  full `Directives` override) — the default CDN set drops it.
- Seed the dev-bypass user app-side; set `DevBypassEnvVar` to the app's name
  (e.g. `GEARBOX_DEV_AUTO_LOGIN`).

### libation deferred UI work (fold into its cutover)

- Full-width fixed-top header (gearbox pattern) — see the earlier session.
- Adopt web-core's richer `toast.js` and (later) `command-palette.js`.

### Pre-extraction cleanup already handled in web-core

table.templ dedup, metrics split (MetricCard out), namespace renames
(`WebCoreKeymap`, `.datagrid`), CSP env reads removed. When deleting gearbox's
originals, also delete its now-dead duplicates.

## Resume checklist

```bash
cd /Users/dave/src/web-core && go build ./... && go test ./...   # all green
git -C /Users/dave/src/web-core log --oneline | head -20         # ~18 commits
```
