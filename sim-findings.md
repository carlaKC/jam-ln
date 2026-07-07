# Simulator findings — measurement artifacts and assumptions

Observations only. No engine fixes (the engine is read-only). These shape how every
attack's revenue impact must be measured. Ranked by how much they distort the headline
metric.

## 1. The printed "Revenue loss / Revenue gain" line is not a valid attack metric — RESOLVED

**Resolved (2026-07-02):** the simulator now co-simulates a live peacetime (no-attacker)
network alongside the attack network on the same virtual clock and `SIM_SEED`, and both
sides count only *settled* revenue read at the same virtual instant. Because honest
activity is generated per-node (salted by pubkey) and attacker channels are excluded from
honest-node capacity, both networks generate **identical** honest traffic (verified: an
inert `NullAttack` produced the same 417,878 payments in both). This replaces the at-add
CSV replay described below and removes the phantom loss. The rest of this section
documents the original (now-fixed) problem for context; the co-simulation is the fix.

Note the co-simulation also surfaced a real effect: an inert attacker can earn the target
*more* than peacetime when its channels add routing capacity (the sink attacker's 50B
channel to the target lifts settled revenue 23M→36M). That is correct — attacks are scored
vs peacetime, so an attack must overcome any routing benefit its own channels create.

**Unbiasedness validated (exact).** Running `NullAttack` with an attacker channel that
touches *no honest node* (an isolated attacker↔attacker channel, so the honest graph is
literally unchanged) gives peacetime and simulation revenue that are **bit-for-bit equal**:

```
Peacetime revenue (msat):  23,156,321
Simulation revenue (msat): 23,156,321
Revenue loss:              0
```

So the two co-simulated networks have no systematic bias — identical honest inputs produce
identical target revenue exactly (not merely within noise). Any non-zero delta an attack
shows is therefore caused by the attacker's channels-plus-actions, not by the machinery. The
canonical `Null` baseline (`networks/ln_50/attacks/Null/`) uses this non-perturbing
isolated attacker channel.



`summary.txt` compares `simulation_revenue` (the target's earnings in the simulated
attack world) against `peacetime_revenue` (a baseline). Both halves of that comparison
are confounded:

### 1a. Generated vs. replayed traffic are different realisations (~50× apart)

The attack-world honest traffic is **generated live** by sim-ln (seeded by `SIM_SEED`),
whereas `peacetime_revenue` is a **separate realisation replayed from
`peacetime_traffic.csv`**. They are not the same payments, so their totals are not
comparable.

**Demonstration (the decisive one):** run the new `NullAttack` — an attacker that adds
its channels to the graph but takes **no action whatsoever** — on `ln_50` for 30 days:

```
ln-simln-jamming --network-dir networks/ln_50 --attack-type null --target-reputation-percent 1
→ Peacetime revenue (msat):   1,660,349,190
→ Simulation revenue (msat):      33,557,559
→ "Revenue loss in simulation":1,626,791,631   (98% "loss")
```

An attacker doing **nothing** "destroys 98% of revenue" by this metric. The gap is the
generated-vs-replayed mismatch, not an attack. The simulated honest traffic also fails
heavily on `no general resources` (see finding #2), so the simulation target revenue is
already a small fraction of the peacetime projection before any attacker acts.

### 1c. Peacetime counts forwards at *add* time; the live sim counts only *settled* forwards

`forward-builder` records each forward via `report_forward`
(reputation_interceptor.rs:466), which fires inside `inner_add_htlc` **at HTLC-add
time, before the success/fail branch** (line 483) and before the payment's
end-to-end outcome is known. Confirmed empirically: every row in
`peacetime_traffic.csv` has `added_ns == settled_ns`, i.e. the writer stamps both
at add. The CSV has no success column, and `peacetime_from_file` (parsing.rs) sums
`incoming_amt − outgoing_amt` for every target row with **no success filter**. So
`peacetime_revenue` credits the target for every HTLC it ever *accepted locally*,
including payments that subsequently **fail downstream**.

The live sim, by contrast, credits the target only on end-to-end success
(`RevenueInterceptor::notify_resolution` adds the fee only when `res.success`).

This is a counting-semantics mismatch (add-time vs settle-time), present regardless
of runtime — **not** a virtual-time/attack-branch timing bug. Measured directly on a
30-day `NullAttack` over `ln_50` (inert attacker):

```
Target forwards the target accepted locally (succeeded forwards): ~363M msat in fees
Target revenue actually settled end-to-end (simulation_revenue):  ~36M msat
```

i.e. ~90% of the fee value the target locally forwarded was on payments that failed
downstream and so is counted by peacetime but not by the simulation.

### 1d. Why so many payments fail downstream: a congested cold-start network (NOT a snapshot bug)

The downstream failures are overwhelmingly `InterceptorError: no general resources`
(measured: 19,849 of ~20k failures in a 30-day null run), concentrated on **large**
HTLCs (failed forwards avg ~99M msat in vs ~17M for ones that settle): a large HTLC
exceeds a full `general` bucket's liquidity and, in no-bootstrap mode where honest peers
have little reputation, cannot upgrade to `protected`, so it fails.

**The reputation snapshot is faithful** — investigated and ruled out as the cause. On
load, `OutgoingChannel::new` seeds the snapshot value into the `DecayingAverage` at the
load instant (`add_value(value, add_ins)`), so at sim start reputation equals the
snapshot value and decays forward exactly as it did during generation
(`forward_manager.rs` `add_channel`, `outgoing_channel.rs`). The live sim's target
start reputation (10/39 pairs) is the network's genuine cold-start state, not a loading
artifact.

So the high downstream-failure rate is a **real property of the no-bootstrap network**,
present in generation too — during generation those same large HTLCs are also recorded
at add (§1c) even though many fail downstream, which is exactly why peacetime looks so
much larger than the settled simulation revenue. The practical effect stands: the live
"peacetime" world is a congested cold-start (~90% of the target's forwarded fee value
fails to settle) before any attack, which limits attackable headroom. Fixing the
**counting** (§1c: make the baseline count only settled forwards) makes an inert attacker
show ~0 loss; the cold-start congestion itself is a separate realism question.

### Regeneration result (2026-06-30)

Regenerating `ln_50`'s derived files from scratch with the current binary (fresh
`peacetime_traffic.csv` via `forward-builder`, fresh `reputation.csv` via the now-fixed
`reputation-builder`) reduced peacetime inflation
(1.66B → 416M) and exercised the fixed `reputation-builder`, but the inert `NullAttack`
still shows a ~91% phantom "loss" (peacetime 416M vs simulation 36M). Diagnosis above:
the gap is add-time-vs-settle-time counting (1c) compounded by snapshot-fidelity
congestion (1d) — **not** routing diversion (generating traffic on the attack graph
gives the target ~422M/30d, ≈ the no-attacker 416M) and **not** a peacetime-replay
timing bug. **Conclusion unchanged: do not use the peacetime line; measure with the
`NullAttack` CRN baseline (here ~36M msat / 30d on `ln_50`).**

### 1b. In `--attacker-bootstrap` mode the two sides are seeded inconsistently

`simulation_revenue` is **seeded** with the builder's `revenue_<secs>.csv` value, while
`peacetime_revenue` is seeded from the replayed `peacetime_traffic.csv` window
(`RevenueInterceptor::new_with_bootstrap`). These two measures of the same bootstrap
period disagree badly. For `ln_50` + `sink` + 30d bootstrap:

```
revenue_2592000.csv (sim seed):     15,386,355,040
peacetime 30d-window seed:           ~2,470,032,963 (within the 2.47B peacetime total)
```

So the run starts ~12.9B msat "ahead" before the attack does anything, and the whole
12.9B "Revenue gain" the sink run prints is this seeding gap. Over the 12.45-day run the
simulation actually *added* only ~7.4M msat of target revenue on top of the 15.386B seed.

## The measurement protocol that follows from #1

Ignore `peacetime_revenue` as an attack metric. Measure impact by **Common Random
Numbers**: run the *same* attacker graph twice under the same `SIM_SEED` and the same
fixed duration —

- **baseline:** `--attack-type null` (inert attacker), and
- **attack:** the real attack,

— and take `revenue_loss = simulation_revenue(null) − simulation_revenue(attack)`. The
generated honest traffic is identical between the two runs, so the difference is the
attack's causal effect. Prefer **no-bootstrap** runs so both `simulation_revenue` values
start from zero and accumulate only over the controlled window. `NullAttack` lives in
`attacks/null.rs`; point it at the attack's own network dir (copy the attack's
`attacktime_network.json` + `attacker.csv` into `attacks/Null/`).

## 2. Generated honest traffic is dropped by bucketing even with no attacker

During a `NullAttack` run the logs show many `Forwarding failure ... no general resources`
events on honest generated payments. The honest traffic saturates `general` buckets and,
lacking reputation in the no-bootstrap snapshot, cannot be upgraded — so it fails. This is
consistent with the documented artifact "data generation does not implement resource
bucketing." Consequence: the simulation's baseline target revenue (~33.5M msat / 30d on
`ln_50`) is already far below the peacetime projection, so there is limited honest revenue
left for an attacker to deny. Attacks must be judged against the `NullAttack` baseline,
not the peacetime figure.

## 3. Runs are not bit-for-bit deterministic (~0.3% revenue noise) — FIXED

Two identical `NullAttack` invocations produced `simulation_revenue` of 33,557,559 and
33,462,234 msat — a 0.28% difference — despite the fixed `SIM_SEED`. Cause confirmed:
virtual time was anchored to `SystemTime::now()` at startup (main.rs), so the absolute
channel-update timestamps (every update is stamped with the clock's start instant) differed
by the wall-clock seconds elapsed between invocations and perturbed routing tie-breaks.

**Fix applied (2026-07-07):** `main.rs` now anchors virtual time at the wall clock
*truncated to a fixed daily grid* (`quantized_start_time` / `START_TIME_QUANTUM_SECS`), so
repeated runs on the same day start from a byte-identical instant. A fixed constant is not
usable because LDK rejects channel updates whose timestamp is more than two weeks in the
past or a day in the future (`lightning::routing::gossip`, gossip.rs:2483/2489), so the
anchor must stay close to real time; a daily grid is the coarsest quantum that both stays in
that window and makes same-day runs identical.

**Verified:** two 1-day no-monitor `null` runs (`networks/ln_50`) are now byte-identical
in all simulation content — same payments (`13958 … 33966836063 msat … 70.13% success`),
routes, liquidity moves, and settled revenue. The only residual per-run difference is the
payment-hash/preimage *string* (an unseeded preimage RNG, cosmetic — it does not affect
amounts, routing, success/fail, or revenue). So the ~0.3% noise floor is removed; deltas no
longer need a noise margin for same-day baseline-vs-attack comparisons (which, being
co-simulated in one process, already share the start instant exactly).

## 5. `history_from_file` dropped data — broke `reputation-builder` on the virtual-time runtime (FIXED)

`history_from_file` (parsing.rs) splits the traffic CSV into `num_chunks =
num_workers.div_ceil(2)` chunks for parallel reading, then read them with
`for i in 0..breakpoints.len() - 1`, keying the final chunk's end off `i == num_chunks - 1`.
That loop never reached the last chunk, so it **silently dropped ~1/num_chunks of the
file**. On the single-threaded virtual-time runtime (`block_on_virtual_time` →
`current_thread`), `num_workers() == 1` ⇒ `num_chunks == 1` ⇒ `breakpoints.len() == 1` ⇒
the loop ran **zero** times and returned an empty history, so `reputation-builder` failed
immediately with `"at least one entry required in bootstrap history"`.

Consequences:
- Since the tokio-des migration to the single-threaded runtime, `reputation-builder` could
  not read any traffic file at all — so the committed `reputation.csv` / `revenue_*.csv`
  predate the migration and are out of sync with the current binary (the likely root cause
  of the measurement mismatch in #1). `forward-builder` was unaffected because it generates
  traffic via simulation and never calls `history_from_file`.
- Even on a multi-threaded runtime the snapshot was built from only ~`(num_chunks-1)/num_chunks`
  of the traffic, so historical reputation snapshots were built on truncated data.

Fix applied: read every chunk, with the last running to `file_size`
(`for i in 0..breakpoints.len()`, `end = if i == breakpoints.len()-1 { file_size } else
{ breakpoints[i+1] }`). Correct on either runtime; no silent truncation. Note:
`reputation-builder` does not need virtual time — `bootstrap_network_history` replays
forwards at instants computed *relative* to `clock.now()` and never sleeps — so the runtime
choice only affected `num_workers` (and thus this bug), not the resulting snapshot.

## 4. Runtime is attacker-controlled, so the comparison window varies

The simulation runs only until `run_attack` returns (which triggers shutdown). An attack
that terminates quickly accumulates almost no revenue on either side (e.g. no-bootstrap
`sink` dies immediately on "no reputation" and runs just 300 virtual seconds). For a fair
comparison, hold the simulation open for a **fixed** virtual duration matching the
`NullAttack` baseline (`BASELINE_SECS` env var controls the baseline's duration; default
30 days).

## 6. Sustained high-rate in-flight HTLCs are not representable (blocks measuring fast-jamming)

Found while implementing `FastJam` (an attack that floods the target with tiny fast-failing
HTLCs to keep its `general`-bucket slots full). Two harness limitations make this class of
attack currently **unmeasurable**, independent of its economics:

- **In-flight occupancy.** Rapidly-forwarded HTLCs did not register as sustained in-flight
  occupancy in the target's *incoming* `general` bucket: across a run dispatching ~5.3M
  jamming HTLCs, the target's `general_slots_available` on the jammed channel never dropped
  below its full count (193 = 40% of 483), so honest traffic was never denied (only ~5 of
  ~5,670 honest forwards hit `no general resources` — noise). **Resolved by SlotJam
  (`attacks-found.md` #1):** *held* HTLCs do occupy general slots and deny honest traffic
  (SlotJam denies 42% this way). FastJam's HTLCs simply *resolved too fast* — each occupied its
  slot only for the ~150 ms round trip, so sustaining occupancy needed a dispatch rate that
  starved the clock. It's a timing/economics property, not a broken accounting path.
- **Virtual-clock starvation.** A continuous, high-rate `send_to_route` loop keeps the
  single-threaded virtual-time runtime busy, and virtual time only advances at quiescence, so
  the run never reaches its `BASELINE_SECS` deadline, `run_attack` never returns, and no
  `summary.txt` is written. The per-forward analysis writer also emits ~0.5 GB of CSV per
  virtual minute under this load.

Consequence: fast-jamming cannot be run to a measured conclusion in the current harness. Its
economics separately defeat it (the 1% unconditional fee costs the attacker far more than the
revenue it could deny), so this is recorded as a limitation, not a blocker for the study — but
measuring fast-jam properly would need a harness change (rate-limited dispatch on a
multi-threaded clock, or modelling in-flight occupancy directly). See `attacks-found.md` #2.

## 7. General-bucket slot assignment uses an unseeded RNG (non-deterministic)

`GeneralBucket::get_candidate_slots` (`ln-resource-mgr/src/incoming_channel.rs`) picks each
channel's `ASSIGNED_SLOTS` slots by hashing the channel pair with a **fresh random salt**
generated by `rand::rng()` — unseeded, so it differs every run and is not covered by
`SIM_SEED`. This makes the exact slot layout (and therefore any attack or measurement that
depends on which channels collide on shared slots) non-deterministic in principle. In practice
SlotJam's outcome reproduced bit-for-bit (it fills *all* of a pair's slots regardless of which
they are), but a finer-grained slot-collision attack, or exact reproducibility of the general
bucket under load, would require seeding this salt from `SIM_SEED`. Observation only.

## 8. Many held HTLCs make co-simulation runs slow (limits measuring held-HTLC jams)

SlotJam (`attacks-found.md` #1) pins the general bucket with many *held* HTLCs. Two costs make
long fixed-window measurement of such attacks impractical in the current harness:

- **Per-forward O(n) in-flight scans.** `InFlightManager` bookkeeping
  (`bucket_in_flight_count`, `channel_in_flight_risk`, etc.) iterates the whole in-flight map
  on every forward's allocation check, so with `n` held HTLCs each honest forward is O(n). Over
  a long window with hundreds of held HTLCs this is quadratic.
- **Teardown.** Failing/unwinding all the held HTLCs across *both* co-simulated networks at
  shutdown is slow (runs stall at "Waiting for interceptors to shutdown").

Dispatch itself is instant (0 virtual seconds — measured). The practical effect: SlotJam is
comfortably measurable with the revenue-drop monitor on (it stops at the first 5% breach, ~7.5
virtual days), but a monitor-off run over, say, 30 days does not complete cheaply. Measuring an
attack's *total* damage over a long horizon would want an indexed in-flight structure (per
`(incoming_channel, bucket)`) instead of full-map scans.

## 9. Payment sizes scale with node capacity → a fat tail that dominates revenue

sim-ln's `RandomPaymentActivity::payment_amount` draws from a **LogNormal whose variance grows
with node capacity**: `payment_limit = min(source_cap, dest_cap)/2`, `sigma² = 2·(ln(limit) −
ln(expected))`. The mean stays at `expected_payment_amt` (~3.8M msat), but for paths through
**high-capacity** nodes sigma is large, so the distribution has an enormous right tail. The
target's peers are large (44 = 100B, 31 = 84B msat), so payments routed through it reach **~2B
msat**, and because fee ∝ amount those rare giants dominate the target's fee revenue.

Measured on `ln_50` (30-day inert run): **the top 1% of the target's forwards (amount > 1B
msat) carry 95% of its fee revenue**; the other 99% carry 5%.

Why this matters for attacks: those billion-msat forwards have an in-flight risk (∝ amount) far
above even the target's largest reputation (1.45B), so they can **never** be upgraded to
`protected` — they depend entirely on the `general` bucket. So a general-bucket jam
(GeneralJam/SlotJam) denies *exactly* these giants, while normal-sized honest payments upgrade to
`protected` and survive. The result: the general jam's headline revenue loss is almost entirely
the denial of artifact-sized payments, not a property of the mitigation against realistic traffic.
Any attack whose measured impact concentrates in these giants should be treated as riding this
artifact (see the "Affirm the mechanism" step in `attack-discovery.md`). A realistic re-measure
would decouple payment size from routing-node capacity (cap sizes, or a fixed size distribution).
