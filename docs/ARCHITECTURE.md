# Configuration Fabric - architecture

## Systems boundary

Configuration Fabric owns exactly one problem: **distribution and authoritative
delivery state for configuration artifacts that upstream systems have already
produced.**

It does **not**:

* decide desired network intent;
* calculate safe transition sequences between configurations;
* decide which targets belong to which rollout cohort;
* interpret, merge or edit configuration content.

It **does**:

* hold immutable configuration artifacts and prove their integrity;
* resolve an explicit deployment set (targets supplied by upstream) into
  per-target delivery work;
* move the right generation to the right target over an authenticated framed
  protocol;
* record what actually happened at every lifecycle boundary, per target;
* refuse to activate a stale generation, a mismatched digest or a duplicate
  delivery;
* reconcile after either side restarts, without inventing completion;
* explain, deterministically, why each target is where it is and what blocks
  convergence.

## Components

| Component | Executable | Responsibility |
|---|---|---|
| Distributor (controller) | `cf-controller` | Authoritative delivery state, artifact store, scheduling, acknowledgement recording, convergence reporting, inspection control channel |
| Target agent | `cf-agent` | The truth about what one target has activated; apply contracts; stale fencing; idempotent activation |
| Inspection CLI | `cfctl` | Online control channel and offline durable-state inspection; artifact digest helper |

The distributor **dials** targets. Target endpoints are part of the deployment
instruction supplied by upstream, because Configuration Fabric does not discover
targets.

## Typed identity

Nothing important is a bare string or integer. The public types in
`include/cf/ids.hpp` are distinct C++ types, so a `TargetId` cannot be
passed where a `ConfigKey` is expected and a `Generation` cannot be compared
against a `Revision`.

| Concept | Type | Meaning |
|---|---|---|
| Delivery target | `TargetId` | A device or control-plane participant named by upstream |
| Configuration slot | `ConfigKey` | Logical configuration slot on a target; generation ordering is per (target, key) lineage |
| Configuration identity | `ArtifactId` + `Revision` | Producer-assigned identity and revision |
| Delivery ordering | `Generation` | Fabric-assigned monotonic generation within a lineage |
| Content identity | `Digest` | SHA-256 of the artifact bytes |
| Schema identity | `SchemaId` + `SchemaVersion` | Configuration schema the bytes claim |
| Distributor authority | `Epoch` | Incremented on every distributor start; older epochs are fenced |
| Process identity | `IncarnationId` + `Term` | Per-process random incarnation and monotonic target boot term |
| Attempt identity | `AttemptId` + `StreamId` | Retry and wire-stream identity |
| Delivery identity | `DeploymentId` | SHA-256-derived from (target, config key, generation, digest) |

Because `DeploymentId` is derived from content, "the same delivery" means the
same bytes for the same generation on the same target - which is what makes
redelivery idempotent across restarts.

## Lifecycle

```
prepared -> offered -> transferred -> verified -> staged -> applied -> acknowledged
     ________ failed / rejected / retired (accounting states) ________/
```

* `prepared` - the distributor knows what this target should run and holds the bytes.
* `offered` - the target has been told a transfer is coming.
* `transferred` - every byte was accepted by the target.
* `verified` - the target recomputed the digest and it matched.
* `staged` - the target holds the artifact in its staging area.
* `applied` - the target reports the generation active (the activation boundary).
* `acknowledged` - that report was durably recorded under current authority.
* `failed` - retryable; `rejected` - refused on principle; `retired` - superseded.

`acknowledged` is a claim with a precise meaning: a target, under a live
authenticated session with a current incarnation, reported that the exact
(generation, digest) pair is active **and** that report was durably recorded by
the current distributor authority. Losing the acknowledgement message loses the
claim; it is never inferred from silence. When a later session recovers the
claim from a live report, the record is marked
`acknowledgedFromReconcile` and every report says so.

## Apply contracts

A target states what it can honestly do.

* `atomic-activate` - the agent performs exactly one atomic replacement of its
  live pointer. A crash leaves the target on exactly the old or exactly the new
  configuration.
* `prepare-commit-abort` - the target cannot swap atomically, so the agent
  exposes an explicit prepare window. A crash inside the window leaves the live
  area dirty; start-up reconciliation detects it, aborts it, records the
  rollback, and the delivery is re-driven. A commit without an open prepare
  window is refused, because accepting it would silently promote the weaker
  contract to an atomic-looking one.

The requirement side (`require-atomic` / `allow-prepare-commit`) is part of the
deployment instruction. A mismatch is a per-target rejection, not a global
failure.

## Fencing

| Fence | Where | Effect |
|---|---|---|
| Stale generation | agent, on prepare / chunk / stage / commit | Refused before anything is touched |
| Same generation, different digest | agent | Refused as a conflict |
| Older controller epoch | agent, at handshake | Session refused |
| Different incarnation claiming an accepted epoch | agent, at handshake | Session refused |
| Older target boot term | distributor, at handshake | Session refused |
| Superseded generation | distributor scheduler | Delivery retired |
| Stale contact evidence | distributor policy | Forces a session before any state change |
| Replayed attempt/stream | agent idempotency table | Answered from the durable record, never re-applied |

## Persistence

Both sides use the same durable store: an append-only journal of
integrity-checked records plus two alternating snapshot slots.

* Authoritative controller state: node identity, authority epoch, targets,
  deliveries, artifact metadata.
* Target agent state: incarnation and term, controller fence, committed
  generation and digest, prepare window, pending transfers, activation findings.

Properties that are enforced rather than assumed:

* A torn record at the end of the journal is discarded and reported; damage in
  the middle of the file stops the process.
* A sequence gap stops the process; records are never silently skipped.
* Unknown record types stop the process rather than being ignored.
* A gap between the newest loadable snapshot and the journal base stops the
  process: recovery never fabricates the missing records.
* Liveness evidence is **process-local**. Durable state carries a contact
  *timestamp*; the "this process established contact" flag is never persisted and
  never restored, so a restart cannot inherit freshness.
* A verified transfer is reusable: re-offering identical content resumes at the
  full artifact rather than discarding completed work.

## Reconciliation

`reconcileDelivery()` is a pure function over (delivery record, authenticated
session authority, agent report). It returns one of: drive normally, adopt
activation, resume transfer, retire as stale, resolve a prepare window, fence
authority, or unknown at target. It takes no locks, performs no I/O and calls
nothing, so the distributor and the explanation renderer cannot disagree about
what a report means.

After a target restart, the agent's live pointer is the authority for what is
activated: if the durable record and the pointer disagree - the shape of a crash
between the activation switch and the record of it - start-up reconciliation
adopts the pointer and records that it did.

## Scheduling

* One worker per target session; a target is claimed by at most one worker, which
  makes per-target ordering trivial to reason about.
* Decisions come from a pure policy function; the scheduler only maps a decision
  to work and enforces two rate limits: a minimum interval between session
  attempts against one target, and a slow repair probe for deliveries whose retry
  budget is exhausted.
* Retry budgets are per delivery and bounded. A target that comes back with a new
  boot term re-arms the budgets of its failed deliveries exactly once per
  observed restart, with the reason recorded as evidence.
* An operator can force a verification session (`cfctl verify <target>`) to
  re-validate a converged claim; the runtime does not poll converged targets.

## Convergence reporting

For every (target, config key) lineage the report states: the desired generation
and digest, the generation the target is believed to be on, the lifecycle state,
why the target is where it is, what is still pending, and every typed blocker.

`render()` contains no wall-clock timestamps and no addresses, so two runs
over the same durable state produce byte-identical output; `fingerprint()`
reduces the whole report to a short stable digest. There is no global success
bit: partial failure is always reported per target.
