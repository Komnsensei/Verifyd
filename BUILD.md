# BUILD.md — Verifyd

## Quick start

```
node bin/verifyd.cjs demo
```

That runs the full happy-path + negative cases against built-in test data.

## Audit a PDF

```
node bin/verifyd.cjs audit path/to/document.pdf
```

Produces:
- `path/to/document.verifyd-receipt.json` — machine-readable VALF-1 receipt
- After running certify: `path/to/document.verifyd-receipt.certificate.txt` — human-readable certificate

## Generate human-readable certificate

```
node bin/certify.cjs path/to/document.verifyd-receipt.json
```

## Verify a sealed receipt

```
node bin/verifyd.cjs verify path/to/document.verifyd-receipt.json
```

Returns `Chain valid: true` if untampered, `false` if any byte changed.

## Batch audit a folder

```
node bin/batch-audit.cjs auditdeck
```

Processes every PDF in `auditdeck/`, writes receipts + certificates next to each, plus `auditdeck/BATCH_SUMMARY.json`.

## Requirements

- Node.js >= 18
- Zero dependencies. Zero install steps.

## Deploy

This is a CLI library, not a service. Three deploy modes:

### A. As an npm package
```
cd verifyd-ship
npm publish --access public
```
Then any user: `npx verifyd audit document.pdf`

### B. As a single zip download
```
zip -r verifyd-1.0.zip . -x "auditdeck/*"
```
Ship the zip. User unzips, runs `node bin/verifyd.cjs`.

### C. As a hosted SaaS (future)
Wrap `engine/verifyd.cjs` in a Next.js API route. Deploy to Vercel. POST a PDF, return the receipt.

## What's tested

- Happy-path audit (RATIFIED + 95/100)
- Sole-sovereign rejection (forbidden)
- Three-witness rejection (quorum violation)
- DRAFT -> DEPOSITED skip (forbidden)
- PATTERN -> RATIFIED (pattern is not ratification)
- External governance audit (NON_COMPLIANT verdict)
- Chain re-validation after seal

All exercised by `node bin/verifyd.cjs demo`.
