# Configuration Fabric - operations

## Processes

### Distributor

```sh
cf-controller --node ctl-a               --state /var/lib/cf/state               --artifacts /var/lib/cf/artifacts               --control 127.0.0.1:0               --announce-file /run/cf/controller.endpoint               --key-file /etc/cf/secret.key               --plan /etc/cf/plans/edge.plan
```

* `--node` is durable: restarting with the same node id continues the same
  authoritative state under a new authority epoch.
* `--control` with port 0 asks the operating system to choose a port; the
  bound endpoint is written to `--announce-file`.
* `--plan` is repeatable and applied at start-up.
* `--insecure-no-auth` is loud: it disables peer authentication and is
  reported in `status` as a degraded guarantee. It exists for bring-up only.

### Target agent

```sh
cf-agent --target rtr-1          --state /var/lib/cf/rtr-1          --listen 0.0.0.0:7500          --announce-file /run/cf/rtr-1.endpoint          --key-file /etc/cf/secret.key          --guarantee atomic-activate
```

The agent listens; the distributor dials it. `--guarantee` is durable: changing
it for an existing state directory is refused, because it would silently change
what activation means for that target.

## Deployment plans

```
cf-plan 1
set-id edge-2026-01-01
rollout-set rollout/edge
target rtr-1
  class network-device
  guarantee atomic-activate
  config-key fabric/underlay
  artifact cfg/underlay
  revision 42
  generation 7
  schema cf.underlay
  schema-version 3
  digest <64 hex characters>
  size 2048
  requires require-atomic
  media-type text/plain
  producer intent-engine
  source /var/lib/intent/underlay-rtr-1.cfg
  endpoint 10.0.0.11:7500
end
```

The format is strict: bounded lines, bounded targets, case-sensitive keywords, no
unknown keys, a line number in every error, and an exact round trip. `source`
lets the distributor ingest the artifact exactly once; without it the artifact
must already be in the store. `cfctl digest <file>` prints the digest and size
to paste into a plan.

## Inspection

Online:

```sh
cfctl --endpoint 127.0.0.1:9010 --key-file /etc/cf/secret.key status
cfctl ... targets
cfctl ... deliveries
cfctl ... pending
cfctl ... divergence
cfctl ... converge
cfctl ... explain rtr-1
cfctl ... artifacts
cfctl ... verify-artifacts
cfctl ... verify rtr-1
cfctl ... plan /etc/cf/plans/edge.plan
cfctl ... retire <deployment-id> because superseded
cfctl ... lifecycle
cfctl ... shutdown
```

Offline, against a state directory, without opening (or mutating) the store:

```sh
cfctl --state /var/lib/cf/state converge
cfctl --state /var/lib/cf/state --artifacts /var/lib/cf/artifacts verify-artifacts
cfctl --state /var/lib/cf/state journal
cfctl --state /var/lib/cf/state explain rtr-1
```

Offline output always begins with the recovery summary it was derived from, so a
reader can tell a clean replay from a recovered one.

## Reading a convergence report

```
target=rtr-1 key=fabric/underlay desired-generation=7 desired-digest=3f2a... current-generation=6
current-digest=91bc... state=failed guarantee=atomic-activate required=require-atomic outcome=not-converged
  reason: the last attempt failed: digest mismatch at the target
  blockers: digest-mismatch-reported retry-budget-exhausted
  pending:
    - operator action: raise the retry budget or fix the target
```

Blockers are typed and sorted, so they can be alerted on:
`not-yet-delivered`, `delivery-in-flight`, `awaiting-acknowledgement`,
`retry-budget-exhausted`, `target-unreachable`, `target-authority-fenced`,
`guarantee-unsupported`, `artifact-unavailable`, `digest-mismatch-reported`,
`size-mismatch-reported`, `schema-unsupported`, `policy-rejected`,
`target-ahead-of-desired`, `superseded`, `liveness-evidence-stale`,
`prepare-window-open`, `live-pointer-unverified`.

## Failure handling

| Symptom | Meaning | Action |
|---|---|---|
| `retry-budget-exhausted` | The bounded retry budget for that generation is spent | Fix the target, then either raise `--max-attempts` or submit a new generation; a target restart re-arms the budget automatically |
| `liveness-evidence-stale` | No session has been established by the current process | Nothing, if a session is pending; `cfctl verify <target>` forces one |
| `target-ahead-of-desired` | The target is on a newer generation than the plan asks for | Expected during ordered rollout; the delivery is retired rather than pushed backwards |
| `guarantee-unsupported` | The instruction demands atomicity the target cannot provide | Change the instruction (`requires allow-prepare-commit`) or replace the target |
| `prepare-window-open` | The target holds an unresolved prepare/commit window | The distributor aborts it during reconciliation and re-drives |
| `live-pointer-unverified` | The live area and durable state disagreed at start-up | The agent recorded what it did; inspect its log for `adopted-live-pointer` or `aborted-unresolved-prepare` |

## State directory layout

```
<state>/
  controller.snapshot.a|b     two alternating snapshots
  controller.journal          append-only records newer than the snapshot
  agent.snapshot.a|b
  agent.journal
<artifacts>/
  payload/<aa>/<digest>.bin   immutable content
  payload/<aa>/<digest>.meta  metadata record with its own checksum
<agent live area>/
  live/<config key>/current   the atomic activation pointer
  live/<config key>/pending   an open prepare window (prepare/commit/abort only)
  live/<config key>/payload/  retained activated payloads
  staging/<deployment>.part   partially received artifact
```

## Validation-only surfaces

`--fault-inject` exists so the validation suite can stop a process at an exact
protocol boundary. It is never enabled by default and never changes a decision,
only the moment a process dies. Points: `after-offer`, `after-chunk[:n]`,
`after-verify`, `after-stage`, `after-prepare`, `before-commit`,
`after-switch`, `after-commit`, `withhold-ack`, `corrupt-chunk`,
`truncate-transfer`, `drop-after-prepare`, `stale-commit`,
`duplicate-chunk`, `oversize-declare`. An unknown point is a start-up error, so a
typo cannot silently disable a scenario. Each process interprets the points it
has armed; the controller's `after-chunk:n` drops its own connection, while the
agent's `after-chunk:n` terminates the agent after accepting n chunks.
