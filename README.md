# Configuration Fabric

**A vendor-neutral Fabric OS runtime for distributing already-produced network
configuration and proving what each target actually activated.**

Configuration Fabric is a standalone C++20 runtime, built by
[Summon Software Labs](https://github.com/summonlabs). It owns distribution and
authoritative delivery state. It does **not** decide desired network intent,
compute transition sequences or choose rollout cohorts; upstream systems supply
explicit deployment instructions, and this runtime gets the right configuration
generation to the right target with evidence.

## What it actually does

* **Immutable configuration artifacts.** Content-addressed storage with SHA-256
  verification on ingest and on read; a corrupted artifact is quarantined and can
  never be served again.
* **Typed everything.** Targets, configuration keys, artifact identities,
  revisions, generations, epochs, incarnations, attempts and digests are distinct
  C++ types, not interchangeable strings or integers.
* **Tracked distribution.** A framed, checksummed protocol over real TCP sockets
  with bounded payloads, HMAC-SHA256 peer authentication, per-frame sequencing,
  acknowledgements and idempotent redelivery.
* **An explicit lifecycle.** prepared → offered → transferred → verified → staged
  → applied → acknowledged, plus failed / rejected / retired.
* **Stale fencing on both sides.** A target never activates a lower or stale
  generation over a newer authoritative one; a stale controller epoch, a
  conflicting incarnation or a replayed attempt cannot mutate current state.
* **Honest apply contracts.** Targets that can activate atomically say so; targets
  that cannot expose an explicit prepare/commit/abort window, and a crash inside
  that window is detected, aborted and reported rather than papered over.
* **Restart-safe persistence.** Versioned, integrity-checked journals with two
  snapshot slots and conservative recovery. Old liveness evidence is never
  treated as fresh, and a controller restart cannot invent completion.
* **Reconciliation.** After either side restarts, authoritative state is rebuilt
  from live reports - never from assumption - and any activation recovered that
  way is labelled as reconciliation evidence.
* **Partial failure, per target.** There is no global success bit. Every lineage
  reports its own state, its own reason and its own typed blockers.
* **Deterministic convergence summaries.** Byte-identical output for identical
  durable state: no wall-clock timestamps, no addresses, plus a stable
  fingerprint.
* **Inspection tooling.** An online control channel and offline durable-state
  inspection that never mutates what it reads.

## Repository layout

```
include/cf/        public headers (the installed API)
src/               implementation
apps/              cf-controller, cf-agent, cfctl
tests/             the validation suite (unit, property, adversarial, concurrency,
                   process, multiprocess, injection, restart, statetest)
bench/             benchmarks that measure completed work
examples/          an independent downstream find_package consumer
docs/              architecture, operations, proof surfaces, concurrency audit
cmake/             warning policy and the exported package configuration
```

## Build

```sh
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
```

Requirements: CMake 3.21+, a C++20 compiler (MSVC 19.40+ or GCC 12+/Clang 15+),
and a POSIX thread implementation. There are no third-party dependencies.

Options: `CF_BUILD_APPS`, `CF_BUILD_TESTS`, `CF_BUILD_BENCHMARKS`,
`CF_WARNINGS_AS_ERRORS` (default ON), `CF_ENABLE_ASAN`.

## Install and consume

```sh
cmake --install build/release --prefix /opt/configuration-fabric
cmake -S examples/downstream-consumer -B build/downstream       -DCMAKE_PREFIX_PATH=/opt/configuration-fabric
cmake --build build/downstream && ./build/downstream/cf-downstream-consumer
```

The exported target is `ConfigurationFabric::cf_core`.

## Quick start

```sh
# 1. Shared secret (64 hex characters)
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' 
' > /etc/cf/secret.key

# 2. Target agent
cf-agent --target rtr-1 --state /var/lib/cf/rtr-1 --listen 0.0.0.0:7500          --announce-file /run/cf/rtr-1.endpoint --key-file /etc/cf/secret.key

# 3. Describe what rtr-1 should run
cfctl digest /var/lib/intent/underlay-rtr-1.cfg      # prints digest and size
$EDITOR edge.plan                                    # cf-plan format, see docs/

# 4. Distributor
cf-controller --node ctl-a --state /var/lib/cf/state               --artifacts /var/lib/cf/artifacts               --announce-file /run/cf/controller.endpoint               --key-file /etc/cf/secret.key               --plan edge.plan

# 5. Inspect
cfctl --endpoint "$(cat /run/cf/controller.endpoint)" --key-file /etc/cf/secret.key converge
cfctl --endpoint "$(cat /run/cf/controller.endpoint)" --key-file /etc/cf/secret.key explain rtr-1
```

## Status of this release

Version 1.0.0. Release and Debug builds are clean at `/W4 /WX`; the validation
suite passes in Release, Debug and AddressSanitizer configurations. Everything
claimed in `docs/PROOF.md` was executed against the shipped binaries; claims that
were not proven are listed there as UNSUPPORTED.

Measured on the development host (Windows 11 x64, MSVC 19.44, loopback TCP):

| Benchmark | Result (three runs) |
|---|---|
| Artifact store (publish + re-read + verify) | 21–39 MB/s of verified bytes |
| Framing (encode + decode round trip) | 270–282 MB/s |
| End-to-end delivery (controller → agent → acknowledged) | 32/32 deliveries every run, 14–18 deliveries/s |

Benchmarks measure completed work - verified bytes and acknowledged deliveries -
never submission latency.

## Documentation

* `docs/ARCHITECTURE.md` - components, identity model, lifecycle, fencing,
  persistence, reconciliation, scheduling, reporting
* `docs/OPERATIONS.md` - running the processes, plan format, inspection
  commands, reading convergence reports, failure handling, state layout
* `docs/PROOF.md` - every claim with its REAL / SYNTHETIC / UNSUPPORTED label
* `docs/CONCURRENCY.md` - the manual locking, lifetime and cancellation audit

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
