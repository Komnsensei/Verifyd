# AGENTS.md — Codex / Agent instructions

This repo is a self-contained, zero-dependency Node.js compliance audit engine.

## What you should do on first run

1. Read `BUILD.md` for full build/test instructions
2. Run `npm test` to verify all examples pass
3. Run `node bin/verifyd.cjs demo` to see a working audit end-to-end
4. Run `node bin/batch-audit.cjs auditdeck` if you want to batch-audit the
   sample PDFs in `auditdeck/`

## What "ready to deploy" means

- `npm test` exits 0
- Every receipt JSON validates through `verifyd verify`
- Every certificate.txt opens as plain text
- Citations registry `engine/citations.json` loads without error
- All 14 standards listed there resolve in `engine/policy.cjs`

## Hard rules — do not violate

- No external dependencies. Verifyd is intentionally zero-dep.
- No telemetry. No network calls during audit.
- No vendor lock-in. Receipts must remain verifiable offline.
- No single-party ratification. The lattice forbids `tier_0_sovereign`.
- Every policy check must carry citation grounds in its receipt entry.

## When asked to add features

Always:
1. Update `engine/citations.json` first if a new authority is invoked
2. Wire it through `engine/policy.cjs` or `engine/lattice.cjs`
3. Update `bin/certify.cjs` to render it
4. Add an example under `examples/`
5. Re-run `npm test` and confirm clean

## Useful commands

```bash
npm test                                 # full test suite
node bin/verifyd.cjs demo                # smoke test
node bin/verifyd.cjs audit <pdf>         # audit any PDF
node bin/verifyd.cjs verify <receipt>    # verify a receipt
node bin/certify.cjs <receipt>           # render human-readable certificate
node bin/batch-audit.cjs <folder>        # batch audit
```

## Repo layout

See `BUILD.md` for full architecture diagram. Short version:

- `engine/` — the protocol
- `bin/` — CLI entry points
- `examples/` — runnable demos
- `auditdeck/` — sample PDFs for batch testing
