# webcore

Shared web framework for [sarg3nt](https://github.com/sarg3nt) Go web apps. Provides the UI primitives, auth/session/CSRF handling, SSE transport, middleware, and helpers that `gearbox`, `libation`, and future apps all build on, so the look-and-feel and the security-sensitive plumbing live in one place instead of drifting copy-by-copy.

> [!WARNING]
> Pre-1.0 and under active extraction from `gearbox`/`libation`. APIs will move. See [docs/webcore-extraction-plan.md](docs/webcore-extraction-plan.md) for the migration plan and current phase.

## Layout

Two top-level packages — a frontend "skin" and a backend "spine":

```text
ui/      Frontend primitives
  templ/        templ components (alerts, badge, toast, modal, table, login, …)
  static/js/    toast, command-palette, datagrid, sse, focus-trap, keymap, …
  static/css/   utilities + component styles (buttons, cards, modals, datagrid)
  assets.go     //go:embed static  →  ui.StaticFiles

core/    Backend primitives
  auth/         session + login + CSRF + password + reset (UserStore-driven)
  webauthn/     WebAuthn RP wrapper
  middleware/   SecurityHeaders (CSPConfig), RateLimiter
  errors/       AppError + WriteHTTPError JSON envelopes
  events/       generic pub/sub Hub
  transport/    SSE HTTP handler over events.Hub
  validation/   request validators
  crypto/       AES-256-GCM encryptor
  migrate/      golang-migrate runner over a caller-supplied embed.FS
  responses/    generic JSON envelopes
```

## Design principles

- **Apps own their data.** `core/auth` is driven by a `UserStore` interface and an `AuthUser` interface. Each consuming app implements those against its own database; webcore never imports an app's models.
- **No hardcoded routes or tenancy.** JS helpers that talk to a backend (`api.js`, `chart-sse.js`) take a base URL / URL factory rather than baking in paths.
- **Pre-generated templ.** `ui/templ/*_templ.go` is committed so consumers don't need the same `templ` CLI version to build.

## Consuming webcore

```go
import (
    "github.com/sarg3nt/webcore/core/auth"
    "github.com/sarg3nt/webcore/ui"
)
```

Serve the embedded static assets:

```go
staticFS, _ := fs.Sub(ui.StaticFiles, "static")
r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
```

## Local development

While iterating on webcore alongside a consumer, add a `replace` directive in the consumer's `go.mod`:

```text
replace github.com/sarg3nt/webcore => ../webcore
```

> [!NOTE]
> When you edit files under `ui/static/`, the consuming app's `air` won't see the change automatically (the assets are embedded into webcore, then re-embedded into the consumer at build). `touch` a Go file in the consumer to force an `air` rebuild + re-embed.

Drop the `replace` and pin a tagged version before shipping.

> [!IMPORTANT]
> Never merge a consumer branch that still carries the `replace` directive — consumer CI checks out a single repo and Docker build contexts can't see sibling directories, so the branch only builds on the machine that has both checkouts.

## Releasing and shipping to consumers

1. Land the change on `main` with CI green (build both tag variants, race tests, templ drift check).

2. Tag and push:

   ```bash
   git tag -a vX.Y.Z -m "webcore vX.Y.Z" && git push origin vX.Y.Z
   ```

   Pre-1.0, minor bumps may break APIs; consumers pin exact versions so nothing moves until they opt in.

3. In each consumer (gearbox, libation):

   ```bash
   GOPRIVATE=github.com/sarg3nt/webcore go get github.com/sarg3nt/webcore@vX.Y.Z && go mod tidy
   ```

   `GOPRIVATE` skips the module proxy for the fetch so a just-pushed tag resolves immediately; consumer CI still verifies `go.sum` against the public checksum database.

4. Run the consumer's full suite (and e2e where it exists) against the new pin before merging.

## License

Elastic License 2.0 — see [LICENSE](LICENSE).
