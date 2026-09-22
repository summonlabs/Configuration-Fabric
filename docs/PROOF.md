# Configuration Fabric - proof surfaces

Every claim below is labelled:

* **REAL** - executed in this repository's validation suite against the shipped
  binaries, on the recorded platform.
* **SYNTHETIC** - executed against in-process components or generated inputs.
* **UNSUPPORTED** - not claimed; no evidence exists.

## Platform

All REAL evidence was produced on Windows 11 x64 with MSVC 19.44 (Visual Studio
2022 Build Tools 17.14), C++20, over loopback TCP. POSIX code paths exist in the
source but were **UNSUPPORTED** in this environment: they were never compiled or
run here.

## Distributed behaviour - REAL

Independent executables (`cf-agent.exe`, `cf-controller.exe`, `cfctl.exe`)
communicating over loopback TCP sockets with a framed, checksummed,
HMAC-authenticated protocol. Evidence points:

| Claim | Evidence |
|---|---|
| A controller process delivers an artifact to an agent process and records an acknowledgement | `cf.multiprocess`: `single_target_delivery_converges` |
| One controller serves several targets and reports partial failure per target | `cf.multiprocess`: `one_controller_serves_several_targets_with_partial_failure` |
| A newer generation supersedes and retires the older delivery | `cf.multiprocess`: `second_generation_supersedes_the_first` |
| A guarantee mismatch is rejected for that target only, with the weaker guarantee named | `cf.multiprocess`: `plan_targeting_an_unsupported_guarantee_is_rejected_per_target`, `weaker_guarantee_is_carried_and_activation_still_converges` |
| A peer with the wrong shared secret is refused | `cf.multiprocess`: `authenticated_channel_rejects_a_wrong_secret` |
| Real processes can be spawned, hard-killed and observed to be gone | `cf.process` |
| The inspection CLI reads live state over the control channel and durable state offline | `cf.multiprocess`, `cf.restart` |

## Kill and restart - REAL

Each case kills a real process with the platform's hard-kill primitive (no
cleanup, no flush) and restarts it.

| Claim | Evidence |
|---|---|
| Killed during chunk streaming; restart reconciles and converges | `cf.injection`: `agent_killed_during_chunk_streaming_reconciles_and_converges` |
| Killed after verification, before activation; restart converges | `cf.injection`: `agent_killed_after_verification_converges_after_restart` |
| Killed before the activation switch; the target is still on nothing | `cf.injection`: `agent_killed_before_the_activation_switch_is_recovered` |
| Killed between the switch and the durable record; restart adopts the pointer | `cf.injection`: `agent_killed_after_the_switch_before_the_record_adopts_the_pointer` |
| Killed inside a prepare window; restart aborts it and the delivery is re-driven | `cf.injection`: `prepare_commit_window_killed_mid_window_rolls_back_and_redelivers` |
| Controller killed mid-delivery; restart does not invent completion | `cf.restart`: `controller_restart_does_not_invent_completion` |
| Controller killed after convergence; restart changes nothing and re-submitting is idempotent | `cf.restart`: `controller_restart_after_full_convergence_changes_nothing` |
| A restarted controller reports persisted contact evidence as not current | `cf.restart`: `agent_restart_invalidates_persisted_liveness_evidence` |
| An agent restart produces a fresh incarnation and an incremented term | `cf.restart`: `agent_restart_gets_a_fresh_incarnation_and_term` |
| Both processes killed; durable state still describes the activation and the acknowledgement | `cf.restart`: `agent_state_survives_a_kill_without_cleanup` |

## Protocol faults - REAL

Injected through documented fault points in the shipped executables.

| Claim | Evidence |
|---|---|
| A lost acknowledgement leaves the delivery applied, never acknowledged | `cf.injection`: `withheld_acknowledgement_leaves_the_delivery_applied` |
| A lost acknowledgement is recovered only from a live report after restart | `cf.injection`: `withheld_acknowledgement_is_resolved_by_reconciliation` |
| A controller disconnect mid-transfer resumes from the target's byte count | `cf.injection`: `controller_disconnect_during_transfer_is_resumed_not_restarted` |
| A corrupted chunk is refused and never activated | `cf.injection`: `corrupt_chunk_is_refused_and_never_activated` |
| A truncated transfer is reported as a size mismatch | `cf.injection`: `truncated_transfer_is_reported_as_a_size_mismatch` |
| An oversized size declaration is refused and nothing is activated | `cf.injection`: `oversized_declaration_is_refused` |
| A stale commit is fenced by the target | `cf.injection`: `stale_commit_is_fenced_by_the_target` |

## Protocol semantics - SYNTHETIC (real codecs, in-process peers)

The protocol codecs, framing layer, agent state machine and reconciliation
decision function are exercised in-process over real loopback sockets in
`cf.unit`, `cf.adversarial` and `cf.property`:

* digest mismatch prevents activation and destroys the staged bytes;
* duplicate delivery is answered from the durable record and never re-applied;
* duplicate and reordered chunks are refused while the transfer still converges;
* a stale generation is refused without touching the live area;
* the wrong key, a stale controller epoch and a conflicting incarnation are all
  fenced at the handshake;
* an atomic target refuses a prepare window; a prepare/commit target refuses a
  bare commit;
* every single-byte corruption of every codec is refused;
* random payloads never crash any decoder.

## Adversarial input - SYNTHETIC

* truncation at every length of every codec and of the framing layer;
* single-byte corruption at every offset of every codec, frame header, frame
  payload, metadata record and snapshot;
* oversized length declarations (including a hostile 4 GiB frame header);
* unknown flags, reserved bits, message types and enumerators;
* foreign and torn journal files, mid-file corruption, snapshot damage in one and
  both slots, snapshot/journal gaps;
* artifact store corruption, quarantine, budget exhaustion and partial publishes.

## Concurrency - SYNTHETIC

* parallel publish and verify from eight threads against one artifact store;
* the distributor's worker pool, control channel and shutdown path are exercised
  by every multiprocess test;
* a seeded randomized state machine drives the policy and lifecycle machine
  through 300 scenarios, asserting the invariants the scheduler depends on.

## Not claimed - UNSUPPORTED

* **POSIX builds.** The source contains POSIX paths, but nothing POSIX was
  compiled or executed here.
* **Real network hardware.** Every socket is loopback TCP on the host that ran
  the tests. No switch, route reflector, line card or firmware was involved.
* **RDMA, NVLink, multi-GPU, switch-vendor or firmware APIs.** Not present in
  this repository at all.
* **Cryptographic acceleration or HSM integration.** HMAC-SHA256 and ChaCha20 are
  implemented in portable C++ and validated against published vectors; they are
  not claimed to be constant-time against an attacker who can measure cache
  behaviour, and no hardware root of trust exists.
* **Scale beyond the configured budgets.** The runtime bounds targets, live
  deliveries, artifacts, payload sizes, retries and durable growth, and refuses
  work beyond those bounds; no large-scale deployment was run.
* **Cross-platform durability.** NTFS rename and flush semantics were used;
  directory-entry durability on other filesystems was not tested.
