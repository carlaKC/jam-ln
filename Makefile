check-code:
	cargo fmt --verbose --check --all -- --color always
	cargo clippy --all-features --all-targets --color always -- -D warnings

stable-output:
	@if [ -n "$$(git status --porcelain)" ]; then \
    	echo "Error: There are unstaged or uncommitted changes after running 'make check-code'."; \
    	exit 1; \
	else \
		echo "No unstaged or uncommitted changes found."; \
	fi

check: check-code stable-output

install-tools:
	cargo install --locked --path ln-simln-jamming --bin reputation-builder
	cargo install --locked --path ln-simln-jamming --bin forward-builder

install:
	cargo install --locked --path ln-simln-jamming

# ============================================================================
# Slot / liquidity jamming experiments — one command, data grabbed automatically
# ============================================================================
# `make <attack>` builds the binaries, generates the peacetime traffic + reputation
# snapshot if they're missing (cached afterwards), positions the attacker, runs the
# attack, and prints the summary. Override any VAR=value:
#
#   make slow-slot-jam                                   # quick demo (~20 min first run)
#   make slow-slot-jam JAM_DURATION=8w TRAFFIC_DURATION=10w   # the headline economics
#   make fast-slot-jam REPUTATION_ALGO=gradual           # compare an algorithm
#   make sim-clean-data                                  # drop generated data to regenerate
#   make sim-help                                        # list the knobs

NET               ?= networks/ln_slow_jam
SPEEDUP           ?= 200
# How long to sustain the jam. TRAFFIC_DURATION must be >= JAM_DURATION (the live revenue
# counterfactual replays the raw traffic file over the jam).
JAM_DURATION      ?= 1d
# Peacetime traffic to generate. Kept short: reputation-builder --allow-boost tiles it to fill the
# (unchanged, protocol-default) 6-month reputation window, so a week of traffic bootstraps full
# reputation without generating months of data. Grow it for longer jams.
TRAFFIC_DURATION  ?= 1w
REPUTATION_ALGO   ?= original
# Experiment placement (defaults reproduce the busy, low-base-fee target in ln_slow_jam):
TARGET_ALIAS      ?= 2
CHANNEL_TO_JAM    ?= 570646534881280
SENDER_ALIAS      ?= 25
RECEIVER_ALIAS    ?= 70
# Fee on the target->receiver channel (the hop the held HTLCs exit through) — drives the attacker's
# one-time entry cost via htlc_risk, not the denied revenue. We model 0-base-fee target channels (a
# common LN policy): with 0 base, dust slot-jam HTLCs carry ~no fee so their htlc_risk ~ 0 and entry
# collapses to the revenue threshold. The proportional fee still gates large liquidity-jam HTLCs.
RECEIVER_BASE_FEE ?= 0
RECEIVER_PROP_FEE ?= 100
LABEL             ?= $(ATTACK)

SIM   := ./target/release/ln-simln-jamming
FWD   := ./target/release/forward-builder
REP   := ./target/release/reputation-builder
SETUP := python3 ln-simln-jamming/scripts/setup_attack_network.py

.PHONY: bins
bins:
	cargo build --release --bins

# Prerequisites generated on demand and cached. Order-only dep on `bins` so an updated
# binary doesn't force traffic/reputation to regenerate.
$(NET)/peacetime_traffic.csv: | bins
	@echo ">> generating $(TRAFFIC_DURATION) of peacetime traffic (one-time, cached)..."
	$(FWD) --network-dir $(NET) --duration $(TRAFFIC_DURATION)

$(NET)/reputation.csv: $(NET)/peacetime_traffic.csv | bins
	@echo ">> bootstrapping reputation snapshot from $(TRAFFIC_DURATION) of traffic (boosted to fill the full window)..."
	$(REP) --network-dir $(NET) --allow-boost

# The three slot/liquidity attacks. ATTACK = CLI name, DIR = results/<DIR> (Debug form).
.PHONY: slow-slot-jam fast-slot-jam fast-liq-jam
slow-slot-jam: ; @$(MAKE) --no-print-directory run ATTACK=slow-slot-jam DIR=SlowSlotJam
fast-slot-jam: ; @$(MAKE) --no-print-directory run ATTACK=fast-slot-jam DIR=FastSlotJam
fast-liq-jam:  ; @$(MAKE) --no-print-directory run ATTACK=fast-liq-jam  DIR=FastLiqJam

.PHONY: run
run: bins $(NET)/reputation.csv
	@echo ">> positioning attacker for $(DIR)..."
	$(SETUP) --network-dir $(NET) --attack $(DIR) --target-alias $(TARGET_ALIAS) \
		--channel-to-jam-scid $(CHANNEL_TO_JAM) --sender-alias $(SENDER_ALIAS) \
		--receiver-alias $(RECEIVER_ALIAS) --receiver-base-fee $(RECEIVER_BASE_FEE) \
		--receiver-prop-fee $(RECEIVER_PROP_FEE)
	@echo ">> running $(ATTACK) (jam $(JAM_DURATION), speedup $(SPEEDUP), algo $(REPUTATION_ALGO))..."
	$(SIM) --network-dir $(NET) --attack-type $(ATTACK) --target-alias $(TARGET_ALIAS) \
		--channel-to-jam-scid $(CHANNEL_TO_JAM) --jam-duration $(JAM_DURATION) \
		--clock-speedup $(SPEEDUP) --reputation-algo $(REPUTATION_ALGO) \
		--target-reputation-percent 1 --label $(LABEL)
	@$(MAKE) --no-print-directory sim-results DIR=$(DIR) LABEL=$(LABEL)

.PHONY: sim-results
sim-results:
	@echo ""; echo "===== $(DIR) / $(LABEL) summary ====="
	@cat "$$(ls -dt results/$(DIR)/$(LABEL)/*/summary.txt 2>/dev/null | head -1)" 2>/dev/null \
		|| echo "(no summary found for results/$(DIR)/$(LABEL))"

.PHONY: sim-clean-data
sim-clean-data:
	rm -f $(NET)/peacetime_traffic.csv $(NET)/reputation.csv
	@echo "removed generated traffic + reputation for $(NET); next run regenerates them"

.PHONY: sim-help
sim-help:
	@echo "Attacks:   make {slow-slot-jam | fast-slot-jam | fast-liq-jam}"
	@echo "Knobs (VAR=value):"
	@echo "  NET=$(NET)                  network directory"
	@echo "  JAM_DURATION=$(JAM_DURATION)             how long to sustain the jam"
	@echo "  TRAFFIC_DURATION=$(TRAFFIC_DURATION)     peacetime traffic to generate (>= JAM_DURATION)"
	@echo "  SPEEDUP=$(SPEEDUP)                 clock speedup (keep <= 200)"
	@echo "  REPUTATION_ALGO=$(REPUTATION_ALGO)     original | gradual"
	@echo "  TARGET_ALIAS / CHANNEL_TO_JAM / SENDER_ALIAS / RECEIVER_ALIAS / RECEIVER_BASE_FEE"
	@echo "Other:     make sim-clean-data   (regenerate traffic/reputation)"
