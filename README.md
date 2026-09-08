# bugbounty-toolkit (C#)

A collection of small, single-purpose C# console tools for **authorized** web
security testing and bug-bounty work — recon, analysis, and clean reporting.
Each tool is its own project under `tools/`, is documented by a header comment
at the top of its `Program.cs` explaining *what it is* and *what it's for*, and
shares one dependency-free library, `Toolkit.Core`.

> **Scope & ethics.** These tools send requests to, and analyze data from, web
> targets. Only use them against systems you own or have **explicit written
> authorization** to test. Unauthorized scanning or testing may be illegal. You
> are responsible for how you use this.

## Status

This is **batch 1 of a planned set of 30 tools**. Ten are implemented, compiled,
and tested; the rest are scoped below and will be added in the same style. See
"Roadmap" for the full list.

## Requirements

- .NET SDK 8.0 or newer.

## Build & test

The repo builds **fully offline** — it uses only the .NET base class library, and
a `nuget.config` clears package sources so no restore hits the network.

```sh
dotnet build                              # builds everything
dotnet run --project tests/Toolkit.Tests  # runs the Core test suite
```

Run any tool with `dotnet run`:

```sh
dotnet run --project tools/jwt-inspector -- <token>
dotnet run --project tools/api-inventory -- --har capture.har
```

Or publish a single tool to a standalone binary:

```sh
dotnet publish tools/cors-auditor -c Release -o ./bin-cors
./bin-cors/cors-auditor --url https://api.target.com/me
```

## Implemented tools (batch 1)

| Tool | What it does |
|------|--------------|
| **api-inventory** | Turns a HAR capture into a de-duplicated inventory of endpoints (methods, params, auth), normalizing `/users/12` → `/users/{id}`. |
| **jwt-inspector** | Decodes a JWT and flags weaknesses: `alg=none`, unsigned, missing/expired `exp`, long lifetime, secrets in claims. No cracking. |
| **response-differ** | Fetches two URLs (or reads two saved bodies) and diffs status, headers, and body lines. |
| **cors-auditor** | Probes a URL with crafted `Origin` headers and flags reflected origins, `null` trust, and wildcard-with-credentials. |
| **redirect-chain-analyzer** | Follows a redirect chain hop-by-hop, flagging HTTPS→HTTP downgrades and cross-host jumps. |
| **open-redirect-checker** | Fires common open-redirect payloads at a `FUZZ`-marked parameter and reports any that land off-host. |
| **redaction-tool** | Strips secrets (JWTs, bearer tokens, cookies, API/AWS keys, emails) from evidence before you share it. |
| **json-csv-exporter** | Flattens a JSON array of objects into CSV with dotted columns for nested fields. |
| **markdown-finding-template** | Emits a standardized Markdown write-up for a finding, or a full report from a findings JSON file. |
| **finding-deduplicator** | Collapses duplicate findings by a stable title+target+severity signature. |

Every tool prints usage with `--help`, and its `Program.cs` opens with a full
explanation of the tool's purpose and typical workflow.

## Roadmap (remaining 20)

Grouped by workflow stage. Same conventions: one project per tool, header-comment
explanation, shared `Toolkit.Core`, authorized-use only.

**Discovery & mapping**
- `parameter-miner-lite` — discover hidden request parameters by observing response changes.
- `graphql-inspector` — run/inspect GraphQL introspection and surface types, queries, mutations.
- `openapi-auth-matrix` — from an OpenAPI spec, build an endpoint × required-auth matrix.
- `schema-response-validator` — validate live responses against an OpenAPI/JSON schema.
- `change-monitor` — snapshot endpoints and diff them over time to catch new surface.

**Access control**
- `idor-matrix` — replay a request across accounts/IDs and matrix which identities can read what.
- `role-diff` — compare what different roles can reach across a set of endpoints.
- `mass-assignment-field-reviewer` — highlight object fields that might be settable via mass assignment.
- `pagination-boundary-tester` — probe pagination limits/offsets for over-exposure and leaks.

**Protocol / config behavior**
- `csrf-token-observer` — observe CSRF token presence, rotation, and enforcement.
- `cache-behavior-checker` — inspect caching headers/behavior for cache-deception/poisoning signals.
- `rate-limit-observer` — measure whether and how rate limiting kicks in.
- `file-upload-reviewer` — review upload responses for type/extension/path handling issues.
- `subdomain-takeover-reviewer` — check dangling DNS/CNAMEs for takeover candidates.

**Flow & timing**
- `oauth-flow-recorder` — record an OAuth redirect flow and its parameters for review.
- `business-flow-recorder` — capture a multi-step business flow as a replayable sequence.
- `race-condition-observer` — fire concurrent identical requests and observe race outcomes.
- `webhook-request-recorder` — a local listener that logs inbound webhook/callback requests.

**Evidence & intake**
- `burp-request-importer` — parse Burp saved-items XML into normalized requests.
- `request-replay-sanitizer` — replay a saved request with secrets sanitized.
- `report-evidence-generator` — assemble a finding's request/response evidence into a bundle.

## Layout

```
bugbounty-toolkit/
├── BugBountyToolkit.sln
├── Directory.Build.props        # shared TFM / nullable / implicit usings
├── nuget.config                 # clears sources -> offline build
├── src/Toolkit.Core/            # shared library (HTTP, HAR, JWT, CORS, findings, redaction, JSON/CSV)
├── tools/<tool-name>/           # one console project per tool
└── tests/Toolkit.Tests/         # self-contained test runner (no framework)
```

## Design notes

- **Zero external packages.** Everything uses the .NET BCL, so it builds without
  network access and has no supply-chain surface.
- **Logic lives in `Toolkit.Core`, tools are thin.** Each `Program.cs` is mostly
  CLI + presentation; the testable logic (parsing, analysis) sits in the library.
- **Findings are a shared type** with a stable signature, so analysis tools,
  the deduplicator, and the Markdown reporter all interoperate.

## License

MIT — see `LICENSE`.
