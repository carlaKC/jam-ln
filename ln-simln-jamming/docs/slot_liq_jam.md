# Slot & liquidity jamming experiments

Protected-bucket jamming attacks that hold a target channel's protected resources and refill
reputation as it decays, so the jam can be sustained. They let you measure **what it costs an
attacker to keep a channel dark vs. the revenue that channel earns**, against any reputation
algorithm.

Attacks (all configured by one implementation, `attacks/slot_liq_jam.rs`):

| `--attack-type` | fills protected by | hold | repeats |
|---|---|---|---|
| `slow-slot-jam` | one HTLC **per slot** (dust) | full duration | no |
| `fast-slot-jam` | one HTLC per slot (dust) | ~85s | yes, until `--jam-duration` |
| `fast-liq-jam` | one **large** HTLC (exhausts liquidity) | ~85s | yes, until `--jam-duration` |

(`slow_jam` already covers slow-liquidity jamming.)

## Quick start (one command)

```sh
make slow-slot-jam        # or: fast-slot-jam, fast-liq-jam
```

That single command **grabs everything it needs automatically**: it builds the binaries, generates
the peacetime traffic and reputation snapshot if they're missing (cached afterwards), positions the
attacker around the target, runs the attack, and prints the summary. Override any knob inline:

```sh
make fast-slot-jam REPUTATION_ALGO=gradual               # same attack against another algorithm
make sim-clean-data                                       # drop generated data to regenerate
make sim-help                                             # list all knobs
```

The **defaults run a quick (~20 min first time) demo** with the **protocol-default windows**
(14-day revenue, 6-month reputation): only a week of traffic is generated, and
`reputation-builder --allow-boost` tiles it to fill the full reputation window, so reputation is
bootstrapped over the real window without generating months of data. The demo proves the pipeline
and the cost/denied relationship; absolute numbers grow with the hold.

To sustain the jam for longer (the headline amortization), grow the hold — and the traffic, since
the live revenue counterfactual replays the raw traffic over the jam:

```sh
make slow-slot-jam JAM_DURATION=8w TRAFFIC_DURATION=8w
```

The rest of this doc explains what these commands do under the hood and how to read the results.

## Prerequisites (the network directory)

`--network-dir <dir>` must contain:

| file | what it is | produced by |
|---|---|---|
| `peacetime_network.json` | the honest graph (nodes, channels, fee policies) | provided / your topology |
| `peacetime_traffic.csv` | forward history used to bootstrap reputation **and** replayed as the live + counterfactual traffic during the attack | `forward-builder` |
| `reputation.csv` | bootstrapped reputation snapshot the sim seeds from | `reputation-builder` |
| `target.txt` | alias of the node under attack | you |
| `attacks/<AttackType>/attacktime_network.json` | graph during the attack = peacetime graph **+ attacker channels** | derived from peacetime |
| `attacks/<AttackType>/attacker.csv` | attacker aliases (e.g. `70,25`) | you |

Build the traffic + reputation:

```sh
# 1. generate peacetime traffic (see forward-builder --help; --duration accepts 7d / 6m)
cargo run --release --bin forward-builder -- --network-dir <dir> --duration 6m

# 2. bootstrap the reputation snapshot from it
cargo run --release --bin reputation-builder -- --network-dir <dir>
```

The `attacks/<AttackType>/` directory is named after the `Debug` form of the attack
(`SlowSlotJam`, `FastSlotJam`, `FastLiqJam`). Reuse one attack's `attacktime_network.json` for
another by copying the directory.

### Attacker placement (the one non-obvious requirement)

The attacker must be **positioned around the target** for the routes to exist:

- attacker **receiver** ↔ target  (reputation is built/held over this channel)
- attacker **sender** ↔ target  (build route: `sender → target → receiver`)
- attacker **sender** ↔ peer  (jam route: `sender → peer → target → receiver`, where the
  `peer ↔ target` channel is the one being jammed)

Add these as attacker channels in `attacktime_network.json` only (they're allowed to differ from
the peacetime graph because the endpoints are listed in `attacker.csv`). Adding connectivity for
the attacker is realistic — anyone can open channels.

## Running an experiment

```sh
cargo run --release --bin ln-simln-jamming -- \
  --network-dir <dir> \
  --attack-type slow-slot-jam \
  --channel-to-jam-scid <scid> \   # which target channel to jam; peer derived from the graph
  --jam-duration 8w \              # how long to sustain (slow: hold; fast: repeat window)
  --clock-speedup 200 \            # KEEP <= ~200: latency*speedup must stay < 90s resolution period
  --target-reputation-percent 1 \  # relax the pre-flight gate (target need not be highly reputable)
  --reputation-algo original \     # algorithm under test: original | gradual
  --label my-run                   # results/<Attack>/<label>/<timestamp>/
```

Key parameters:

- **`--clock-speedup`** — wall-time accelerator. Must stay `<= ~200`: the latency interceptor's
  sleep is multiplied by the speedup in sim-time, and if it exceeds the 90s resolution period every
  forward's effective fee zeroes out and reputation can't be built (upstream issue #127).
- **`--jam-duration`** — holding for several revenue windows is what makes the one-time entry cost
  amortize below the (accumulating) revenue denied.
- **`--channel-to-jam-scid`** — re-point the attack at any target channel without recompiling.
- **`--reputation-algo`** — run the same attack against each algorithm to compare economics.

## Reading the output (`results/<Attack>/<label>/<ts>/summary.txt`)

```
SlowSlotJam ran for (seconds): 4838587
Peacetime revenue (msat): 51869334          # target's total fees with no attacker
Simulation revenue (msat): 30738607         # target's fees during attack (incl. attacker fees!)
Revenue loss in simulation: 21130727        # net loss = peacetime - simulation
...
Target start reputation (pairs): 12/105     # good-reputation channel pairs before
Target end reputation (pairs): 0/105        # ... and after (collateral: reputation destroyed)
Attacker cost (msat): 29890461 total = 29369000 entry + 521461 sustaining across 17 cycle(s)
Honest revenue denied (msat): 51021188      # peacetime - simulation + attacker fees (see below)
Attacker cost / honest revenue denied: 0.586
```

How to read it:

- **Attacker cost** splits into a one-time **entry** (build reputation to clear the channel's
  revenue threshold) and a recurring **sustaining** cost (decay-driven refills over the hold). The
  sustaining figure is typically scraps — that's the "pay once, hold cheaply" result.
- **Honest revenue denied** corrects a confound: the attacker builds reputation by routing *through
  the target*, so its fees are paid *to* the target and inflate `Simulation revenue`. Adding them
  back (`peacetime − simulation + attacker fees`) recovers the honest revenue actually blocked.
- **Cost / honest revenue denied** is the headline. `< 1` means jamming is cheaper than the revenue
  it denies; because the cost is dominated by the one-time entry, the ratio falls as
  `--jam-duration` grows (≈ `revenue_window / jam_duration`).
- Note the attacker's fees flow to the victim, so this is a **denial-of-service / griefing** result
  (service blocked + reputation destroyed), not net revenue extraction.

## Asserting the thesis

The cost is driven by `entry ≈ channel revenue threshold` + `sustaining ≈ slots × per-HTLC fee ×
hold` — both depend on the **fee policy**, not the channel's throughput. Two levers to vary:

1. **Target a busy, low-base-fee channel** (`--channel-to-jam-scid`): the per-HTLC opportunity cost
   (hence sustaining cost) scales with the base fee of the target→receiver channel. Dust HTLCs on a
   ~0 base-fee channel make slot jamming far cheaper than liquidity jamming for the same bucket.
2. **Hold longer** (`--jam-duration`): the entry amortizes; cost/denied → 0 as the hold grows.

Run the same command across `--reputation-algo {original,gradual}` (and any future algorithm) to
compare whether the algorithm changes the entry/sustaining economics.

## Worked example (the headline result)

Against the `ln_slow_jam` network, targeting a high-revenue, low-base-fee channel:

1. **Pick a target** the attacker can reach: node alias `2` (~83k sat/2w revenue) is adjacent to the
   attacker receiver (alias `70`). Set `target.txt` to `2`.
2. **Position the attacker** by adding two channels to `attacks/SlowSlotJam/attacktime_network.json`
   (cloning an existing attacker-sender channel's shape): `25 ↔ 2` (build route) and `25 ↔ 13`
   (jam route into node 2's busiest channel, `2 ↔ 13`, scid `570646534881280`, ~28.6k sat, 0 base).
3. **Make the cost lever low-fee**: the held HTLCs exit via the target→receiver channel `2 → 70`,
   so its base fee drives `htlc_risk`. Set `2 → 70` base fee `1000 → 1` in that same graph.
   (Reputation does not need rebuilding — the attacker channels carry no peacetime traffic.)

```sh
ln-simln-jamming --network-dir networks/ln_slow_jam --attack-type slow-slot-jam \
  --channel-to-jam-scid 570646534881280 --jam-duration 8w \
  --clock-speedup 200 --target-reputation-percent 1
```

Result (8-week hold ≈ 4 revenue windows):

| | sat |
|---|---|
| Attacker cost (entry 29.4k + sustaining ~0.5k over 17 cycles) | ~29,890 |
| Honest revenue denied (98% of node 2's income) | ~51,021 |
| **cost / denied** | **0.59** |
| Target reputation pairs | 12/105 → 0/105 (wiped) |

The same setup at `--jam-duration 1d` gives ratio ~32 (entry not amortized); 8 weeks → 0.59; the
ratio keeps falling with duration. This is the thesis: on a busy, low-base-fee channel, a sustained
slot jam costs a fraction of the revenue it denies — a cheap denial-of-service (the attacker's fees
flow to the victim, so it isn't profit extraction, but service and reputation are destroyed).
