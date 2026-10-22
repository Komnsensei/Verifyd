# Incident response runbook

Sentinel is a detection and evidence system, not an automated enforcement
system. This runbook assumes the operator is authorized to administer the
monitored host and the systems whose logs are integrated.

## 0. Ground rules

- Do not delete or edit evidence files. Copy them; verify the chain first.
- Do not terminate processes or block addresses based on a single low-severity
  heuristic. Confirm ownership and business context first.
- Do not rotate credentials until compromise is plausible; rotation destroys
  the ability to observe the attacker's next move. If a credential is confirmed
  compromised, rotate immediately through the approved provider process.
- Sentinel starts in `detect` mode and cannot change firewall rules itself.

## 1. Alert intake

Severity comes from the rubric, not from the alert text:

| Severity | Score | Suggested first response |
|---|---|---|
| critical | >= 80 or `critical: true` | immediate; treat as possible access-control failure |
| high | >= 50 | within 30 minutes |
| medium | >= 25 | same business day |
| low | < 25 | review in the next triage batch |

These are response targets, not guarantees. A critical alert deserves a human
decision before any automated response.

## 2. First 15 minutes

1. Open the alert record from `/alerts/recent` or the evidence file.
2. Record the alert id, rule id, entity, first/last seen, score and evidence.
3. Verify the evidence chain:
   ```
   node bin/sentinel.cjs verify --config <config>
   ```
4. Establish facts:
   - Is the principal expected for this route and time?
   - Is the source IP a known integration, office range or cloud egress?
   - Was there a deployment or batch job in the same window?
5. Scope: search evidence for the same principal, IP, route and process.
6. Preserve: copy `state/` and the current `verify` output to the incident
   record before changing configuration.
7. Decide: expected (allowlist with expiry, document why), suspicious (escalate),
   or confirmed incident (follow the org IR plan).

## 3. Rule-specific triage

| Rule | Questions | Likely benign explanation |
|---|---|---|
| AUTH_FAIL_BURST | Is the principal real? Is the source expected? Any success after? | Expired token, misconfigured client, SSO outage |
| RATE_LIMIT_BURST | Is the client a known integration? Was there a retry storm? | Retry loop, load test |
| DENIED_THEN_SUCCESS | Was authorization changed legitimately? Who changed it? | Role grant completed during the window |
| SEQUENTIAL_ENUMERATION | Was this a scheduled export? Is the data classification high? | Reporting job, migration |
| BULK_RESPONSE_VOLUME | Was the download expected? Where did the bytes go? | Backup, analytics export |
| SENSITIVE_ROUTE_REPEAT | Is the client allowlisted? Is the rate above baseline? | Monitoring probe, integration poll |
| PROTECTED_UNAUTHENTICATED | Is gateway auth enforced for this route? | Misrouted request that should have been blocked (still a finding) |
| NEW_LISTENER | Which process owns the port? Is it signed? Was it installed? | Legitimate new service or patch |
| PROCESS_FROM_TEMP | What is the parent? Is the image signed? What is its hash? | Installer running from a temp directory |
| DEFENDER_DETECTION | What did Defender do? Is the threat active? | Test file, blocked commodity malware |
| FILE_INTEGRITY_CHANGE | Was there a deployment? Who changed it? | Config rollout, certificate renewal |
| DB_BULK_READ | Was the query authorized? Where did the data go? | Reporting, replication |
| DB_AUTH_FAILURE | Is the principal expected? Any success after? | Expired secret, rotated password |
| DB_NEW_IDENTITY | Who requested it? What will it be used for? | Approved migration or new integration |
| DB_PRIVILEGE_CHANGE | Is there a change ticket? Does it meet least privilege? | Approved grant |
| HOST_AUTH_FAILURE_BURST | Password spray? Any success from the same source? | Service account with a stale password |
| CORRELATED_ACTIVITY | Read the component alerts; do not treat the sum as a new fact | Multiple expected operations in one window |

## 4. Evidence handling

- Evidence is append-only JSONL with `prev`/`hash` on every record.
- `verify` checks hashes, sequence continuity and the retention anchor.
- A torn final line after a crash is reported as `truncated_tail` and ignored;
  it is not silently repaired.
- `HASH_MISMATCH`, `CHAIN_BROKEN`, `SEQ_GAP` or `MISSING_HISTORY` means the
  evidence is not trustworthy. Stop the service, preserve the directory, and
  investigate before writing more.
- Redaction happens before hashing. Authorization headers, cookies, API keys,
  JWTs and password-like fields are not recoverable from the store.
- Retention deletes whole rotated files and records an anchor. Copy evidence
  before changing `retention_days` or `max_files`.

## 5. Service health procedures

### Adapter UNAVAILABLE

```
node bin/sentinel.cjs coverage --config <config>
```

Read the reason: platform mismatch, path missing, permission denied, PowerShell
timeout, audit policy not enabled. Fix the source or accept the documented blind
spot. Do not mark an adapter ACTIVE by editing its status; status is derived.

### Chain verification failure

1. Stop the task (`Stop-ScheduledTask`).
2. Copy `state/` to read-only storage.
3. Run `verify --json` and record the first failing file/line.
4. Compare the file with the last known-good copy or backup.
5. Do not delete records to "fix" verification.

### Store near capacity

`self.health` emits `store_utilization_high` above 90% of the active file.
Rotate or lower `store.max_bytes`, and confirm retention still meets policy.
Never delete the active file while the service is running.

### Missed polls

`MISSED_POLL_INTERVAL` means an adapter exceeded three intervals without a
successful poll. Check PowerShell timeouts, oversized event-log queries, disk
pressure and CPU. The diagnostic is rate-limited; absence of repeats does not
mean recovery - check `coverage`.

### Webhook outage

`dispatcher.status` shows `UNAVAILABLE` with a reason. Alerts remain in
`state/alerts.queue.jsonl`. When the receiver returns, delivery resumes with
backoff; check `dispatcher.queued`, `delivered`, `dead_letter`. Dead-lettered
alerts are still in the evidence store and can be replayed manually from the
incident record.

## 6. Response actions

All actions are gated:

1. `detection.mode: "respond"` (not the default `detect`);
2. `actions.enabled: true`;
3. a configured authorized target URL for that action;
4. `actions.dry_run` remains `true` until deliberately changed.

The only action types are signed control requests to an operator-owned gateway
or WAF endpoint:

- `gateway_rate_limit` (threshold: medium, requires a source IP, default TTL 300s);
- `waf_block` (threshold: high, requires a source IP, default TTL 900s);
- `credential_rotation` (threshold: high, requires a principal): a signed request
  to an approved identity endpoint. Sentinel does not hold identity-provider
  credentials and never rotates anything itself; the endpoint remains
  operator-owned and operator-approved.

Sentinel never edits local firewall rules, never kills processes, never delays
requests with a tarpit, and never fabricates responses.

Credential revocation is never performed by Sentinel. Even the rotation request
only reaches an endpoint you configured and armed. Record the action id, time,
operator and scope in the incident record, and confirm with the identity team.

## 7. Sample alerts

From `node bin/sentinel.cjs simulate --scenario all --json`:

```json
{
  "rule_id": "AUTH_FAIL_BURST",
  "severity": "low",
  "score": 15,
  "title": "Repeated authentication failures",
  "entity": { "principal": "alice", "ip": "203.0.113.9", "route": "/api/v1/session" },
  "evidence": {
    "failures": 5,
    "window_ms": 300000,
    "statuses": [401],
    "first_failure_at": "2026-01-15T09:00:00.000Z",
    "last_failure_at": "2026-01-15T09:00:32.000Z"
  },
  "recommended_response": [
    "Confirm the principal and source address are expected",
    "Check identity-provider logs for the same pattern",
    "Rotate credentials only if compromise is confirmed"
  ]
}
```

```json
{
  "rule_id": "NEW_LISTENER",
  "severity": "low",
  "score": 15,
  "entity": { "process": "unknown.exe", "host": "sim-host" },
  "evidence": { "address": "0.0.0.0", "port": 4444, "pid": 8123, "baseline_ports": 12 }
}
```

Full generated set: [samples/alerts.json](samples/alerts.json).

## 8. After the incident

- Record the final disposition: expected, false positive, or confirmed.
- Add an allowlist only for confirmed expected traffic, with a reason and expiry.
- Tune one threshold at a time; preserve the previous value in the change record.
- Re-run `npm run test:sentinel` after any rule, redaction or store change.
- Update the coverage matrix if a new source was integrated or removed.
- Review whether the blind spot that mattered is now covered by a real audit log.
