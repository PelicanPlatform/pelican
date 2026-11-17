# Implementation plan

Status: carried out. This is the plan as it was handed to the agents; `README.md` section 11 records what changed along the way.

This plan splits the work in `README.md` into packages that can be built by separate agents. Each package owns a set of files. No two packages that run at the same time touch the same file.

## Rules for every package

1. **Additive only.** Do not change what existing code does. With `Tracing.Enabled` false, the only new work on any request path is a boolean check or a no-op span.
1. **Stay inside your files.** Edit only the files listed for your package. If you need a change elsewhere, report it; do not make it.
1. **No new module dependencies.** Only the foundation package edits `go.mod`, `go.sum` and `docs/parameters.yaml`.
1. **Keep diffs to existing files thin.** Put span helpers and attribute keys in a new `tracing.go` in your package. Existing functions get a few call lines, not restructured bodies.
1. **Never record secrets.** No request headers, no query strings, no tokens. Record errors with `tracing.RecordError`.
1. **Follow `AGENTS.md`.** License header on new Go files, three import groups, no `time.Sleep` in tests, `param` not `viper`.
1. **Test what you add.** Use `tracing/tracingtest`. Include one test showing that nothing is sent or recorded when tracing is disabled.
1. **Build only your packages.** Other agents are editing other packages in the same working tree. A compile error in a file you do not own is theirs; rebuild a little later.
1. **Leave git alone.** No commits, branches, stashes or pushes.
1. **Report** the files you changed, anything you did differently from the design, and anything you could not do.

## Phase 1 (two packages in parallel)

### F: Foundation

Everything the service packages compile against.

| Files                                                                          | Work                                                                                                                                                   |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tracing/*.go` (new)                                                           | The API in `README.md` section 4.2, with the behaviour in 4.3.                                                                                         |
| `tracing/tracingtest/*.go` (new)                                               | `Setup(t)` with an in-memory exporter.                                                                                                                 |
| `docs/parameters.yaml`, generated `param/*.go`, `config/parameter_defaults.go` | The five parameters in section 4.1, then `go generate ./generate`.                                                                                     |
| `go.mod`, `go.sum`                                                             | Make `go.opentelemetry.io/otel`, `otel/sdk`, `otel/trace` and `otlptracehttp` direct dependencies, with `otlptracehttp` at the same version as `otel`. |
| `pelican_url/discovery.go`                                                     | The `TracingEndpoint` field.                                                                                                                           |
| `config/config.go`                                                             | Fill `TracingEndpoint` in `discoverFederationImpl` and `SetFederation`.                                                                                |
| `director/discovery.go`, `director/discovery_test.go`                          | Serve the field.                                                                                                                                       |
| `launchers/launcher.go`                                                        | `tracing.Init`, `tracing.OfferEndpoint`, and the shutdown task.                                                                                        |

Done when: `go build ./...` passes with both build tags, the `tracing` tests pass, the discovery test covers the new field both set and unset, and `go generate ./...` leaves no diff.

### D: Demo scaffolding

| Files                                | Work                            |
| ------------------------------------ | ------------------------------- |
| `design/opentelemetry/demo/**` (new) | Everything in `demo/README.md`. |

Done when: `docker compose up` brings up the federation and the observability stack, and the exerciser downloads objects. Traces are verified after phase 2.

## Phase 2 (four packages in parallel, after F)

### C: Client

| Files                                                                                      | Work                                                                                                                            |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `client/tracing.go` (new), `client/handle_http.go`, `client/main.go`, `client/director.go` | Section 5 spans and context.                                                                                                    |
| `cmd/object_get.go`, `cmd/plugin.go`                                                       | `tracing.Init` after `config.InitClient`; `tracing.Flush` after transfers finish.                                               |
| `client/*_test.go` (new files)                                                             | Span tree for a download against a stub federation; `traceparent` on the director and download requests; nothing when disabled. |

### R: Director

| Files                                                                                                                                                    | Work                                                                                 |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `director/tracing.go` (new), `director/director.go`, `director/sort.go`, `director/sort_algorithms.go`, `director/stat.go`, `director/sort_utilities.go` | Section 6.1 to 6.3.                                                                  |
| `director/*_test.go` (new files)                                                                                                                         | Redirect span with attributes and decision event; stat `HEAD` carries `traceparent`. |

Not `director/discovery.go`; the foundation owns it.

### O: Origin

| Files                                                                                        | Work                                                                                                                 |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `origin_serve/tracing.go` (new), `origin_serve/handlers.go`, `origin_serve/backend_https.go` | Section 8.1 and 8.2.                                                                                                 |
| `origin_serve/*_test.go` (new files)                                                         | Server span joins an incoming `traceparent`; authorize and read children; denied request recorded without the token. |

### K: Cache

| Files                                                                                                    | Work                                                                 |
| -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `local_cache/tracing.go` (new), `local_cache/persistent_cache_api.go`, `local_cache/persistent_cache.go` | Section 7.                                                           |
| `local_cache/*_test.go` (new files)                                                                      | Miss then hit using the existing stub federation; shared-fetch link. |

The cache depends on the client package only through context: it passes a context holding its span to `NewTransferJob` and `Stat`. It needs no client code change of its own.

## Phase 3 (after phase 2)

### I: Integration and documentation

| Files                                                                                                          | Work                                                                     |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `e2e_fed_tests/tracing_test.go` (new)                                                                          | The end-to-end test in `README.md` section 10.                           |
| `docs/app/monitoring-pelican-services/tracing/page.mdx` (new), `docs/app/monitoring-pelican-services/_meta.js` | Operator documentation.                                                  |
| `docs/pelican-http-headers.md`                                                                                 | A `traceparent` entry.                                                   |
| `design/opentelemetry/demo/**`                                                                                 | Run the demo against the finished binaries and fix what the traces show. |

## Phase 4: Review

1. An independent review of each package's diff against the design and the rules above.
1. Fixes.
1. Review again, until a pass finds nothing that needs changing.

## Phase 5: Coherence

Read the whole change as one piece. Look for a guard added in one package that belongs in the `tracing` package, the same helper written twice, attribute keys that disagree between services, and anything a review fix patched locally that has a cleaner home.
