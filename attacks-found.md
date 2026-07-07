# Attacks found — ranked by revenue loss per unit of attacker cost

Revenue loss is measured against the **live co-simulated peacetime network** (no attacker),
Common-Random-Numbers-matched to the attack run (`sim-findings.md` §1). All runs on
`networks/ln_50_v2` (regenerated from scratch with the current binary), seed
`13995354354227336701`, `--target-reputation-percent 1`, no attacker bootstrap.

## Summary

| # | Attack | Revenue loss | Attacker cost (honest) | Verdict |
|---|--------|-------------|------------------------|---------|
| 1 | **SlotJam** | 42% (4.30M msat) | ~1.83M msat (7 channels + ~0.43M capital + 2.7k fees) | **caveated** — real vs this traffic, but the loss is a generation artifact (see below) |
| — | GeneralJam | 41% (4.2M msat) | ~3.0M msat (min(14, 140) jam channels, now charged) | same effect + same artifact caveat as SlotJam |
| 2 | FastJam | none measurable | unconditional fee ≫ damage | **finding** (economics + harness limit) |
| 3 | LoopedHtlc | 0 from the loops | dominated by its bundled jam + priming gifts | **finding** (loops can't be admitted) |
| 4 | Inflation | 5% net, ROI ≈ −25× | 17.2M fees + ~20.7M capital | **finding** (self-defeating) |

**Headline:** the mitigation holds up better than the raw numbers first suggested. A general-bucket
jam (SlotJam with real held HTLCs, or GeneralJam via the helper) *does* post a ~42% revenue loss
cheaply — **but affirming the mechanism (per `attack-discovery.md`) showed the loss is almost
entirely the denial of a handful of billion-msat payments that can never reach `protected`, and
those giants are an artifact of the capacity-scaled payment-size generator (`sim-findings.md` #9),
not a property of realistic traffic.** Normal-sized honest payments correctly upgrade to
`protected` under the jam and survive. The three "clever" attacks (fast-jamming, reputation-looping,
threshold inflation) each fail for *principled, structural* reasons. Net: no clean win yet — the
plausible general-jam headline is artifact-driven, and the mitigation resists the sophisticated
levers.

## Systematic re-verification (2026-07-06)

Every attack was re-run and its mechanism affirmed from the logs (per the `attack-discovery.md`
gate): forward-outcome distribution, loss-by-forward-size, per-network settled count vs average
fee, and the inert-channel baseline. The decisive column is **what actually drives the number**.

| Attack | Loss | Settled forwards (peace → attack) | What actually drives it | Verdict |
|--------|------|-----------------------------------|-------------------------|---------|
| **Null** | 0 (exact) | 15175 → 15169, avg fee 1527 = 1527 | nothing (unbiased); **95% of fees from the 1% of forwards > 1B msat, in the no-attacker baseline** | validated baseline + confirms the artifact is in the *traffic* |
| **SlotJam** | 42% | 4984 → 4994, avg fee 2036 → **1171** | same count, half the avg fee → the >1B giants are stripped (95% of fees); normal traffic still rides `general` | artifact-driven, not a clean win |
| **GeneralJam** | 42% | 4984 → 4891, avg fee 2036 → **1217** | 6,468 normal forwards **upgrade to `protected`**; only the 68 giants fail → same artifact | artifact-driven |
| **LoopedHtlc** | 23% | 4984 → 4761, avg fee 2036 → 1638 | loops do nothing (target reputation **9/40 → 8/40**); the loss is the bundled general jam (same giant artifact) minus its own priming gift | finding — loops inert; loss is a weaker GeneralJam |
| **FastJam** | none | — (no summary) | floods 523k of its own fast-fail HTLCs, starves the virtual clock; never denies honest traffic | finding — unmeasurable + uneconomic (`sim-findings.md` #6) |
| **Inflation** | 5% | 7853 → **3905**, avg fee 1730 → **3306** | *fewer* honest forwards (6,696 fail `no general resources`) but the attacker gifts high-fee inflation payments that swamp the loss; cost 17.2M | finding — self-defeating |

**Overarching conclusion.** Every attack that posts a revenue loss (SlotJam, GeneralJam, and
LoopedHtlc's bundled jam) draws that loss from the **same source: denying the billion-msat "giant"
payments** that can never reach `protected` because their in-flight risk exceeds any reachable
reputation. Those giants carry ~95% of the target's fee revenue *and are present in the no-attacker
Null baseline*, so they are a property of sim-ln's capacity-scaled payment-size generator
(`sim-findings.md` #9), not of the mitigation. Normal-sized honest traffic upgrades to `protected`
and survives every jam. So **there is no clean win against the mitigation on realistic traffic** —
the headline losses are the setup (the payment-size artifact), and the sophisticated levers
(fast-jam, reputation loops, inflation) fail on their own terms. The correct next step is to
re-measure with payment sizes decoupled from routing-node capacity.

---

## 1. SlotJam — the real, cheap general-bucket jam (WIN)

**The mechanism (why it's cheap).** The general bucket is not a single pool: each *(incoming
channel I, outgoing channel O)* pair is assigned a fixed `ASSIGNED_SLOTS = 20` slots (salted-random
from the 193), and an HTLC forwarding I→O consumes `ceil(amount / slot_size)` of them
(`slot_size = 40%·capacity / 193`). So occupancy is bounded **per channel pair**, and — crucially —
an unaccountable HTLC can sit in the bucket for up to the ~2-week `revenue_window`. To deny honest
I→O traffic we just **hold** enough tiny unaccountable HTLCs on the I→O path to fill O's 20 assigned
slots in I's bucket. A tiny amount takes one slot, so the capital locked is negligible; the only
real costs are the attacker's channels to the target's peers and the 1% unconditional fee, paid
once per held HTLC. This is the realistic version of the jam GeneralJam (#—) could only fake with
the `ChannelJammer` helper — and it lands where FastJam failed, because it **holds** (low dispatch
rate, no clock starvation) and held HTLCs genuinely occupy slots.

**Setup.** Two attacker nodes: sender (50) with a small channel to each of the target's *incoming*
peers, receiver (51) with a channel to the target's biggest peer (44). For each high-value pair,
route `sender → peer_I → target → peer_44 → receiver` and hold the HTLC at the receiver until the
run ends. By default it jams the 6 pairs whose traffic exits the target's largest channel (peer 44)
— where most of its forwarding value flows. `SLOTJAM_MAX_PAIRS` / `SLOTJAM_HTLCS_PER_PAIR` tune it.

**Result** (`results/SlotJam/`, reproducible bit-for-bit across runs):

| | |
|---|---|
| Peacetime revenue | 10,148,124 msat |
| Simulation revenue | 5,850,101 msat |
| **Revenue loss** | **4,298,023 msat (42.4%)** |
| Runtime | 648,000 s (~7.5 d; stopped by the revenue-drop monitor) |
| Held HTLCs / pairs jammed | 96 / 6 |
| Graph channels opened | 7 |

**Cost — honest accounting.** Channel opens 7 × 200k = 1,400,000 msat; unconditional fees 2,660
msat; channel capital 7 × 100M × 3% × 7.5/365 ≈ 431,550 msat; held-HTLC capital (96 × 10k) ≈ 592
msat. **Total ≈ 1,834,802 msat to deny 4,298,023 msat → ROI ≈ 2.3×.** (Capital shrinks further with
smaller attacker channels — 100M is far more than the ~1M each actually needs to carry the held
HTLCs.)

**Measurement note.** The figure is the *cumulative* loss over the ~7.5-day window during which
the jam is active (the revenue-drop monitor stops the run at the first 5% breach). The corrected
attack holds every jamming HTLC until shutdown, so the jam is active for the whole window — i.e.
42% is a *sustained* reduction, not a transient. Cross-validated by GeneralJam's helper producing
the same ~41%. Caveat: a clean monitor-off measurement over a *longer* fixed window is currently
harness-limited — failing/tearing down ~120 held HTLCs across the two co-simulated networks is
slow (`sim-findings.md` #8) — so total damage past 7.5 days isn't cheaply measurable here. Dispatch
itself is instant (0 virtual seconds).

**Verdict: caveated — the loss is a generation artifact, not a clean win.** Affirming the mechanism
(per `attack-discovery.md`) showed the 42% does **not** come from denying honest traffic broadly:
under the jam the target still forwards the same *count* of payments, and normal-sized honest
payments **upgrade to `protected` and succeed** (the peers *do* have reputation — 6,468 small
payments upgrade under a full jam). The loss is almost entirely the denial of a handful of
**billion-msat payments** whose in-flight risk (∝ amount) exceeds even the target's 1.45B
reputation, so they can *never* reach `protected` and depend on `general`. Those giants carry ~95%
of the target's fee revenue and are an artifact of the capacity-scaled payment-size generator
(`sim-findings.md` #9). So the mitigation actually protects realistic-sized traffic; SlotJam only
denies artifact-sized payments. The mechanism (cheap held-HTLC general jam, per-pair-bounded slots,
~2-week holds) is sound and cheap, and remains the template — but against realistic traffic (no
billion-msat tail, or a reputation-headroom jam that also shuts `protected`) the general jam alone
should deny far less. Re-measure on decoupled payment sizes before calling it a win.

**Note on determinism:** the per-channel slot assignment uses an *unseeded* RNG (`rand::rng()` in
`incoming_channel.rs::get_candidate_slots`), so it is non-deterministic in principle; in practice
SlotJam's outcome reproduced bit-for-bit here. Flagged in `sim-findings.md`.

## —. GeneralJam — the same jam, faked by the `ChannelJammer` helper

**Mechanism.** Jam the `general` bucket of every one of the target's channels (via the
`ChannelJammer` helper) and hold. Honest unaccountable traffic that no longer fits `general`
must fall back to the one-shot `congestion` bucket or be upgraded to `protected` (which needs
reputation); the traffic that can do neither fails, so the target forwards and earns less.

**Result** (`results/GeneralJam/`):

| | |
|---|---|
| Peacetime revenue | 10,148,124 msat |
| Simulation revenue | 5,952,933 msat |
| **Revenue loss** | **4,195,191 msat (41%)** |
| Runtime | 648,000 s (~7.5 d; stopped by the revenue-drop monitor at >5% loss) |
| General jammed channels | 7 (all of the target's) |
| Graph channels opened | 1 (token attacker channel) |

**Cost — the honest accounting.** The summary charges only the 1 token graph channel
(200 sat). But the `ChannelJammer` helper does *not* charge what really holding 7 general
buckets full costs: in expectation ~20 channels per jammed channel, so ~**140 channels**
(~28,000 sat open cost) plus their capital and the unconditional fees on the jamming HTLCs.
Capital on the token channel is negligible; the ~140 real jamming channels dominate.

**Verdict.** Confirms the measurement pipeline end-to-end (a real 41% loss vs peacetime, far
beyond the ~0.3% noise floor), but the `ChannelJammer` helper does not charge what really holding
the buckets full costs, so *as priced here* it looks like a loss. **SlotJam (#1) is the real,
cheap version** — same denial, held with actual HTLCs, at ~1.83M msat instead of ~28M. Keep
GeneralJam as the quick way to check the *effect* of a full jam; use SlotJam for the true cost.

## 2. FastJam — exhaust general-bucket slots with fast-failing HTLCs (finding)

**Mechanism.** Drive an endless stream of tiny (1000 msat), fast-failing HTLCs along
`attacker_sender(51) → honest_peer → target(22) → attacker_receiver(50)`, failing each instantly
at `intercept_attacker_receive`. Routing *in* through an honest peer makes each HTLC occupy a
slot in the target's peer→target `general` bucket (the mitigation checks resources on the
*incoming* channel). A refill loop with per-channel in-flight tracking tries to hold ~193 (the
40%-of-483 general slot count) in flight on each of the target's two highest-capacity peers.
`intercept_attacker_htlc` fails any honest relay so the attacker gifts no routing capacity.

**Result: no measurable revenue movement.** Verified the attack fires (logs show the target
forwarding the jamming HTLCs; `--attack-type` resolves; attacker channels/aliases load). But:
- the target's `general_slots_available` on the jammed channel **never dropped below 193** (the
  bucket stayed empty) even across a run dispatching ~5.3M jamming HTLCs;
- only ~5 of ~5,670 honest forwards hit `no general resources` — noise, not denial.

**Why (two independent reasons):**
1. **Economics (the mitigation working as designed).** Every attempt pays the 1% unconditional
   fee; holding ~193 slots full requires a very high dispatch rate, and against the target's
   ~0.007 settled honest forwards/second the attacker pays orders of magnitude more in
   unconditional fees than the revenue it could ever deny. Fast-jamming is uneconomic here — the
   unconditional fee's exact purpose.
2. **Harness limitation (`sim-findings.md` §6).** Rapidly-forwarded HTLCs did not register as
   sustained in-flight occupancy in the target's incoming `general` bucket, and a continuous
   high-rate `send_to_route` loop starves the single-threaded virtual-time runtime (virtual time
   only advances at quiescence), so the run never reached its deadline and produced no
   `summary.txt`. So this attack cannot currently be *measured* to completion, independent of its
   economics.

**Verdict: finding.** Uneconomic by design, and not measurable without a harness change. Code on
`attacks/fast_jam.rs`; run knob `FASTJAM_HOLD_MS`.

## 3. LoopedHtlc — accountable HTLC loops for reputation damage (finding)

**Mechanism.** Loop accountable HTLCs `attacker(50) → entry_peer(47) → target(22) → mid_peer →
target → receiver(51)`, holding the final hop past `resolution_period` so the target's forward
over an honest `target→mid_peer` channel resolves slowly, booking a negative effective fee
against that channel's *outgoing* reputation. Bundled with a general-bucket jam so that, once
`general` is full, honest traffic must be upgraded to `protected` over the (intended-to-be
damaged) channel. The receiver's channel with the target is reputation-primed first.

**Result: the looped mechanism moved ZERO revenue.** Verified via logs: all 3 loop HTLCs were
failed at the first honest hop with `outcome fail due to no reputation`; the target's reputation
was unchanged (9/40 pairs). An exhaustive viability check
(`networks/ln_50_v2/attacks/LoopedHtlc/viability_check.py`) found **0 viable (entry, mid) pairs**.

**Why (a mitigation property, not a bug).** The mitigation drops an accountable HTLC whose
in-flight opportunity-cost risk exceeds a hop's reputation. A multi-hop loop accumulates CLTV, so
the risk multiplier is ~1479× — relaying even a 1000-msat base-fee HTLC needs ~1.48M reputation.
The peers worth damaging (high target→peer reputation: 44, 42, 8) have tiny peer→target
reputation, so they drop the loop on the *return* crossing (no slow resolution, no damage); the
peers with enough peer→target reputation to relay (5, 4, 31) have low target→peer reputation
and/or high target-incoming-revenue that lifts the first-crossing threshold out of reach. No path
satisfies entry + first-crossing-threshold + return-crossing reputation at once.

**Revenue attribution.** The ~2.2–2.3M loss the run shows is **not** from the loops — it is the
bundled general jam (a weaker GeneralJam), and it is *reduced* by the priming payments, which are
successful forwards that gift the target ~2M msat (an instance of the inflation-masking effect
below). GeneralJam alone did more damage (4.2M) without the priming gift, so **LoopedHtlc is
strictly worse than GeneralJam here.**

**Cost.** Summary total 2.64M msat (600k open for 3 channels + ~2.04M fees, dominated by the ~2M
priming gift) + ~0.57M capital + the un-modelled general-jam helper cost (~28M) — more than the
damage on every axis.

**Verdict: finding.** Loops can't be admitted; the observed loss is a masked, weaker GeneralJam.
Code on `attacks/looped_htlc.rs`. A loop *could* work only where one channel has high target→peer
AND high peer→target reputation simultaneously (none here), or with attacker bootstrap (forbidden
in this config).

## 4. Inflation — raise the target's revenue thresholds to price out peers (finding)

**Mechanism.** Route genuine, fast-settling payments through the target to inflate its per-channel
`incoming_revenue` — which *is* the `incoming_revenue_threshold` a counterparty's reputation must
clear for `protected` access — to price out the target's honest peers, then congest the buckets so
their now-un-upgradable traffic is dropped.

**Result** (`results/Inflation/`): peacetime 13.59M, simulation 12.91M, **loss 679,705 msat (5%)**
— just the monitor's stop line. Dispatched 151 payments (148 settled). Runtime ~12 d.

**Why it is not a win — the structural trap.** Raising `incoming_revenue(target↔P)` by X requires
the target to *settle* forwards whose fees sum to ~X, and those fees ARE the target's revenue:
**threshold-raise ≡ revenue-gifted, 1:1, with no leverage.** The ~9M of threshold inflation here
is ~9M of settled revenue *gifted* to the target, baked into the 12.9M `simulation_revenue`. That
gift props the target's measured revenue *up*, so the very same all-channel jam that GeneralJam
rode to 41% here yields only 5% — inflation makes the target *richer*, not poorer, relative to
pure jamming. Meanwhile the attacker burned **17.2M in routing fees** plus **~20.7M capital
opportunity cost** to deliver that gift: **cost exceeds damage by ~25×.** (A CRN check confirms
the *inert* inflation graph already diverts ~0.70M of the target's traffic for free, so the active
inflation spends 17M+ to add essentially nothing.)

**Generality.** The lockout only bites honest peers whose reputation sits between the old and new
threshold *and* who would otherwise reach `protected` after a jam. In a cold-start / no-bootstrap
network most honest peers can't use `protected` at all, so the jam already denies them and
inflation's marginal lockout is ~nil. Because threshold-raise ≡ revenue-gifted is structural (not
a simulator artifact), **the reverse lever is self-defeating as a revenue-denial attack: you
cannot remove more of the target's revenue than you first hand it.** Pure general-bucket jamming
strictly dominates.

**Verdict: finding.** Code on `attacks/inflation.rs`.
