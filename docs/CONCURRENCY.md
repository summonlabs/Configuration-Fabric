# Configuration Fabric - concurrency and locking audit

This is a manual audit of every mutex, thread and lifetime boundary in the
runtime. It records what the code does now, not what it was intended to do.

## Threads

| Owner | Threads | Notes |
|---|---|---|
| Distributor | `maxConcurrentSessions` worker threads plus one control-accept thread | Workers own one target session at a time |
| Target agent | One session thread plus the accept loop in the same thread | Sessions are serialized: one distributor at a time drives a target |
| Test harness | One server thread per `AgentServer` | Cancels its session on stop |

There is no thread pool shared between the two roles, and no library-internal
threads.

## Mutexes

| Mutex | Scope | Order |
|---|---|---|
| `Distributor::stateMutex_` | Authoritative controller state, artifact store references, claims, session rate limits, verification requests | Outermost |
| `Distributor::connectionsMutex_` | Weak references to live connections, used only by the shutdown path | Leaf; never nested with `stateMutex_` |
| `ArtifactStore::mutex_` | Artifact index and byte accounting | Leaf |
| `Logger::mutex_` | Output stream | Leaf |
| `AgentServer::connectionMutex_` (tests) | Active session handle | Leaf |

**Lock order is stateMutex_ → leaf locks, and nothing else.** The only place
that used to nest them - `statusText()` reading artifact counts while
holding the state lock - now reads the counts first, so no code path acquires two
mutexes in different orders.

## Deliberate absences

* **No callbacks anywhere.** The artifact store, the durable store, the journal,
  the policy function and the log take no callbacks. There is no code path where
  a callee under a lock can re-enter the runtime.
* **No event emission under a lock.** Logging is called after state has been
  updated, and it is callback-free.
* **No socket operation under the state lock.** Handshake, transfer, activation
  and acknowledgement all run outside it; each state change takes the lock
  briefly.
* **No nested lock acquisition inside the state lock** other than the leaf
  mutexes listed above, and no leaf lock is held while acquiring the state lock.

## Re-entrancy checks

* `DurableStore::commit` is only ever called with `stateMutex_` held, and it
  never calls back into the distributor: the codec mutates the state value and
  the journal writes bytes.
* `recordTransition`, `recordFailure`, `recordRejected`,
  `recordRetired`, `adoptActivation`, `acknowledge` and `noteEvent`
  each take the lock exactly once and never call one another while holding it.
* `pickWork` computes decisions under the lock, releases it, and only then
  applies local decisions through `applyLocalDecision`, which takes the lock
  itself.
* The policy function `decide` takes no locks, performs no I/O and calls
  nothing; the explanation renderer calls it outside any lock.
* The reconciliation decision function is likewise pure.
* `Distributor::stop` sets the stop flag, interrupts connections through the
  connections lock, joins workers, then takes the state lock to compact. It never
  holds the connections lock while joining.

## Shutdown and cancellation

* `stop()` is idempotent (`running_.exchange(false)`), signals admission to
  stop, interrupts every live connection, joins workers and the control thread,
  closes the listener and compacts durable state.
* A cancelled operation cannot publish success: every state change is derived
  from evidence that was actually observed, and the drive loop checks the stop
  flag before each protocol step. A worker that observes the stop flag returns
  `Cancelled` and records nothing.
* `Socket::interrupt` sets a cancellation flag and performs a `shutdown()`. The
  read and write paths poll that flag at least every 50 ms, because a
  `select()` already blocked inside the kernel is not woken by a `shutdown()`
  on every platform. This was a measured defect: before the poll was added, a
  cancelled session took the full 10-second idle timeout to return.
* `Listener::interrupt` is a flag plus a bounded poll interval, so a listening
  handle is never closed from another thread.
* No lock is held across a `join()`.

## Bounded resources

| Surface | Bound |
|---|---|
| Wire payload | Negotiated, never above 16 MiB; chunks bounded to half of that |
| Frame decode buffer | At most one maximum frame |
| Message fields | Every string, vector and count has an explicit bound |
| Journal records | `maxRecordBytes` (1 MiB default) |
| Journal growth | Snapshot plus segment restart at a configured byte threshold |
| Snapshot size | 64 MiB default |
| Artifacts | Count, per-artifact size and total bytes |
| Deliveries | Live delivery count, per-lineage history, events per delivery |
| Retries | Per-delivery attempt budget, spaced by bounded backoff |
| Sessions | Worker count, minimum interval per target, repair probe interval |
| Agent transfers | Retained transfers and payloads per key |
| Log lines | Truncated at a bounded length, with a truncation counter |

## Audit result

The audit found and fixed one real ordering hazard (nested artifact access under
the state lock) and one real cancellation defect (a blocked `select()` not
observing a shutdown), both described above. No lock inversion, no callback under
a lock and no re-entrant acquisition remains.
