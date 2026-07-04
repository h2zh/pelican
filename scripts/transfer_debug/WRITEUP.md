# Writeup: Pelican/OSDF transfer-failure debugging multitool

## What was built

A self-contained debugging multitool, `scripts/transfer_debug/pelican_transfer_debug.py`, that automates the questions an operator asks when an object transfer fails in a Pelican federation and then localizes the fault.
It is Python 3 standard-library only (PyYAML is used if present, with a built-in fallback parser), so it can be dropped onto any debugging host.
Transfers run through the real `pelican`/`osdf` client; discovery, authorization, and TLS checks use direct HTTP/TLS so the tool can read the structured detail the CLI hides.

## Files

| File | Purpose |
| --- | --- |
| `pelican_transfer_debug.py` | The tool: probes, diagnosis engine, table/JSON rendering, `--tips` checklist. |
| `config.example.yaml` | Annotated config template (object, backup/control objects, failed/known-good caches, origin, tokens, binary). |
| `README.md` | Full documentation: question-to-probe mapping and diagnosis logic. |

## How it works

1. **Discovery** — resolves the federation via `/.well-known/pelican-configuration`, then queries the Director's `/api/v1.0/director/object` and `/origin` endpoints, parsing `X-Pelican-Namespace`, `X-Pelican-Authorization`, `X-Pelican-Token-Generation`, and the `Link` cache list.
2. **Token match** — decodes the JWT and checks issuer against the Director-advertised issuer(s), expiry/not-before, and `storage.read` scope coverage of the object path.
3. **TLS** — verifies certificates (trust, hostname, expiry) for the Director, both caches, and the origin.
4. **Transfers** — reproduces the failure through the failed cache, pulls a control object from a different object store through it (cache-miss/new-origin path), a backup object from the same origin, a `--direct` origin read bypassing caches, and the same/control objects through a known-good cache.
5. **Diagnosis** — combines outcomes into ranked findings pointing at the object, origin/object store, the failed cache, the origin↔cache network, token/authorization, the Director, or the local client.

## Verification performed

- Compiles cleanly (`py_compile`); `--help` and `--tips` work.
- Token logic unit-checked with synthetic JWTs: correct issuer/scope → PASS; wrong issuer → FAIL with mismatch reason; expired token → FAIL.
- Header parsing verified for `X-Pelican-Namespace`, multi-entry `Link` cache lists, and host/port extraction (bare host, `host:port`, full URL).
- Six synthetic diagnosis scenarios all classify to the expected component: failed cache, single broken object, origin/object store down, origin↔cache network, all-fail (local client), and Director 404.
- Both config paths (PyYAML and the built-in flat parser) produce identical results on the example config; empty values normalize to `None`.
- End-to-end run against an unreachable federation degrades gracefully: downstream probes SKIP instead of misfiring, and the diagnosis correctly stops at "Director / discovery."
- `--json` output is valid JSON with `config` (tokens redacted), `results`, and `diagnosis` sections; colored and plain table rendering both verified.

## Usage

```bash
./pelican_transfer_debug.py -c config.yaml            # full run
./pelican_transfer_debug.py -c config.yaml --json     # machine-readable
./pelican_transfer_debug.py -c config.yaml --no-transfers  # offline probes only
./pelican_transfer_debug.py --tips                    # extra debugging questions
```

## Limitations

- Live transfer probes were not exercised against a real federation from this environment (no external network); the transfer path shells out to the standard `pelican object get --cache/--direct` flags and was validated at the command-construction and failure-summarization level.
- Cache hit vs. miss cannot be forced reliably from a client, so the tool reports per-transfer wall time as a hint and defers deeper hit/miss checks to the `--tips` checklist.
- Token verification is structural (issuer/expiry/scope vs. Director advertisement); it does not validate the JWT signature against the issuer's JWKS.
