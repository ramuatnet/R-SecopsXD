# In-house template pack (newtask.md Phase B, N1)

Curated templates authored in-house — **no clone** of nuclei-templates. Every
template only touches the approved origin (egress rule N8), carries a
`# source:` citation (review gate N9), and is capped at 3 requests.

## Schema (per template YAML)

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Globally unique, `rsec-` prefixed |
| `info.name` | yes | Human title |
| `info.severity` | yes | info / low / medium / high / critical |
| `info.classification.cwe-id` | yes | CWE for category mapping |
| `info.tags` | yes | Comma-separated; must include `rsec` |
| `# source:` | yes | Citation of the public advisory / WSTG section (N9 — lint fails without it) |
| `http` | yes | ≤3 request blocks; every matcher declares `type` + `part` |
| `requires` (index.json) | optional | Capability tag; the runner only executes the template when that capability is confirmed for the target (N5 — kills V3-class waste) |

## Capability gating (N5)

`index.json` maps template → optional `requires` capability. The runner infers
target capabilities from the crawl corpus (e.g. `graphql` when a GraphQL
endpoint is observed) and skips templates whose requirement is not confirmed.
Unknown capability = never guessed = template skipped (I8).

## Lint (N3/N7/N9)

```
npm run lint:templates
```

Checks: required keys, unique ids, `# source:` present, matcher has type+part,
≤3 requests, DSL allowlist (no `code:` protocol, no `javascript:` expressions,
payload lists ≤ 40 items).

## Binary integrity (N6)

`nuclei-pin.json` pins the expected nuclei version and, once the binary is
deployed, its SHA-256 per platform. The adapter verifies at startup and records
the binary version in every finding's provenance. A mismatched hash = engine
unavailable (fail closed).

## Canary (N10)

`npm run canary` — parser canary always runs (canned JSONL → expected
finding); if the pinned binary is installed it additionally runs the pack
against the local vuln-app fixture and asserts expected template hits.
