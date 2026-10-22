# Detection rules

Every score here is an **initial tuning value**, not a calibrated probability.
A score of 30 does not mean "30% malicious". It means "this observation met a
documented condition worth 30 points in this rubric".

Observed facts and heuristic classifications are stored separately:

- `facts.observed: true` and the raw fields (status, bytes, pid, path) are facts.
- `facts.classification: "heuristic"` marks the score as an inference.
- `evidence` lists exactly what fired, including window sizes and counts.

## Rubric

| Rule | Score | Applies to | Condition (defaults) |
|---|---|---|---|
| `AUTH_FAIL_BURST` | 15 | HTTP 401/407, host logon failure | >= 5 failures per entity in `window_ms` |
| `RATE_LIMIT_BURST` | 10 | HTTP 429 | >= 3 responses in `window_ms` |
| `DENIED_THEN_SUCCESS` | 20 | HTTP 401/403 then 2xx | same entity and route inside `window_ms` |
| `SEQUENTIAL_ENUMERATION` | 25 | HTTP GET 2xx | >= 5 distinct pages, or 5 consecutive pages, or >= 10 distinct ids with an 80% consecutive run |
| `BULK_RESPONSE_VOLUME` | 30 | HTTP 2xx with byte count | single response >= 2 MB, or >= 10 MB for one entity in the window (suppressed when a learned baseline says the route is normally this busy) |
| `SENSITIVE_ROUTE_REPEAT` | 20 | HTTP, route matches `sensitive_routes` | >= 10 hits, baseline established and current bucket >= 3x baseline mean |
| `PROTECTED_UNAUTHENTICATED` | 100 | HTTP 2xx, route matches `protected_routes` | no principal, or `facts.authorized === false`; marked critical |
| `NEW_LISTENER` | 15 | `host.listener` | port not in the persisted baseline; allowlisted processes are recorded but not scored |
| `PROCESS_FROM_TEMP` | 20 | `host.process` | image path contains `\Temp\`, `\Tmp\` or `AppData\Local\Temp` |
| `DEFENDER_DETECTION` | 40 | `host.defender` | Defender event 1116/1117 or a parsed threat name |
| `FILE_INTEGRITY_CHANGE` | 15 / 20 | `host.file` | modified/created (15) or deleted (20) |
| `DB_BULK_READ` | 30 | `db.audit` | `rows_read >= 5000` |
| `DB_AUTH_FAILURE` | 15 | `db.audit` | outcome `auth_failure` or `failure` |
| `DB_NEW_IDENTITY` | 20 | `db.audit` | `new_identity: true` or CREATE/ALTER USER/ROLE |
| `DB_PRIVILEGE_CHANGE` | 25 | `db.audit` | `privilege_change: true` or GRANT/REVOKE |
| `HOST_AUTH_FAILURE_BURST` | 15 | `host.session` | >= 5 failed logons per entity in the window |
| `CORRELATED_ACTIVITY` | sum | correlation pass | >= 2 distinct rules for one entity inside the window and combined score >= 50 |

`CORRELATED_ACTIVITY` is capped at 100 and links the component alert ids in
`evidence.components`. It never fires for a single rule.

## Severity

```
severity_thresholds: low 1, medium 25, high 50, critical 80
```

`PROTECTED_UNAUTHENTICATED` is always critical regardless of threshold.
`min_alert_score` (default 10) drops anything smaller from the alert stream; the
underlying events remain in evidence.

## Correlation window

- `detection.window_ms` (default 300000 = 5 minutes) is a sliding window in
  **event time**, not processing time.
- Each rule keeps bounded samples per `entity` (`principal`, else `ip`, else
  `pid`, else path, else adapter).
- Expiry runs at most once per second of event time to keep throughput linear.
- An event backlog replays in its original order instead of collapsing into one
  processing window.

## Dedupe

- Key: `rule_id | entity | route`.
- Cooldown: `detection.dedupe_cooldown_ms` (default 300000).
- Inside the cooldown, repeat detections increment suppression counters and do
  not create new alerts. When the cooldown expires, the next alert carries
  `occurrences` and `suppressed_since_previous` so the operator sees the gap.
- Every suppressed detection still increments `detection.suppressed`, visible in
  `/status`.

## Baseline

Per-route request counts are bucketed in minute windows
(`baseline.bucket_ms`, `buckets`, `min_buckets`).

- `summary()` returns mean and p95 of completed buckets, excluding the current
  one, plus the current/mean `ratio`.
- `alert_ratio` (default 3) is the deviation needed for volume-style rules.
- `require_baseline` (default true) means `SENSITIVE_ROUTE_REPEAT` stays silent
  until a baseline exists. Individual bulk, unauthorized, enumeration and host
  rules still fire during learning.
- The baseline is persisted in `runtime.json` and restored across restarts.

This is a deterministic statistic, not a model. It is deliberately simple so an
operator can explain every suppression.

## Allowlists

`allowlist` entries match when every declared field matches:

```json
{ "ip": "203.0.113.0/24", "route": "/api/v1/export*", "reason": "nightly export job", "until": "2026-12-31T00:00:00.000Z" }
```

Supported fields: `adapter`, `ip` (exact, glob or IPv4 CIDR), `principal`,
`route` (glob), `process`, `path` (glob). Matching events are stored with
`allowlisted: true` and `facts.allowlist_reason`, and are never scored.

Allowlist is not a blocklist and does not change gateway behavior. It is an
acknowledgement with an audit trail.

## What is deliberately not scored

- User-Agent string (including `curl`, `python-requests`, empty UA).
- Missing `Accept-Language` or other browser-only headers.
- Request rate alone, without a baseline deviation or a rule condition.
- A single 401 or 403.
- Being a known scanner unless it exceeds a documented threshold.

## Tuning procedure

1. Run detection-only for at least one full business cycle.
2. Export the observed rates and review `alerts/recent` and evidence.
3. Add allowlists for confirmed integrations; set an expiry so they are revisited.
4. Adjust one threshold at a time and record why in the change ticket.
5. Re-run `npm run test:sentinel` after any rule change. False-positive tests are
   part of the suite, not optional.

Do not lower thresholds to "catch more" without a corresponding allowlist and
response plan; alert fatigue is a security failure mode.
