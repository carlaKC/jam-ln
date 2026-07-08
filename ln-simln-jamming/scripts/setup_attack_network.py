#!/usr/bin/env python3
"""Prepare a network's attack-time graph for a slot/liquidity jamming experiment.

Idempotent and additive: it only touches the small `attacks/<Attack>/attacktime_network.json`
(creating it from the SlowJam template if absent) and never modifies the peacetime graph,
`target.txt`, or the (large) traffic/reputation files. Re-running is a no-op.

It positions the attacker around a chosen target so the jam routes exist, and optionally lowers the
base fee on the target->receiver channel (the channel whose fee drives the attacker's htlc_risk):

  - add  sender  <-> target   (build route:  sender -> target -> receiver)
  - add  sender  <-> peer     (jam route:    sender -> peer -> target -> receiver)
  - set  target  -> receiver  base fee = --receiver-base-fee

The peer is derived from --channel-to-jam-scid (the channel's endpoint that isn't the target).

Usage (see the Makefile, which calls this for you):
  setup_attack_network.py --network-dir networks/ln_slow_jam --attack SlowSlotJam \
      --target-alias 2 --channel-to-jam-scid 570646534881280 \
      --sender-alias 25 --receiver-alias 70 --receiver-base-fee 1
"""
import argparse
import copy
import json
import shutil
import sys
from pathlib import Path


def alias_map(channels):
    m = {}
    for c in channels:
        for s in ("node_1", "node_2"):
            m[c[s]["alias"]] = c[s]["pubkey"]
    return m


def channel_exists(channels, a, b):
    for c in channels:
        ends = {c["node_1"]["alias"], c["node_2"]["alias"]}
        if ends == {a, b}:
            return True
    return False


def synth_channel(scid, honest_alias, honest_pk, attacker_alias, attacker_pk):
    """A generous attacker channel: large capacity, dust min, standard policy."""
    side = lambda alias, pk, cltv, base: {
        "pubkey": pk, "alias": alias, "max_htlc_count": 483,
        "max_in_flight_msat": 50_000_000_000, "min_htlc_size_msat": 1,
        "max_htlc_size_msat": 50_000_000_000, "cltv_expiry_delta": cltv,
        "base_fee": base, "fee_rate_prop": 1,
    }
    return {
        "scid": scid, "capacity_msat": 100_000_000_000,
        "node_1": side(honest_alias, honest_pk, 40, 1000),
        "node_2": side(attacker_alias, attacker_pk, 144, 1000),
        "forward_only": True,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--network-dir", required=True, type=Path)
    ap.add_argument("--attack", required=True, help="attack dir name, e.g. SlowSlotJam")
    ap.add_argument("--target-alias", required=True)
    ap.add_argument("--channel-to-jam-scid", required=True, type=int)
    ap.add_argument("--sender-alias", required=True)
    ap.add_argument("--receiver-alias", required=True)
    ap.add_argument("--receiver-base-fee", type=int, default=1,
                    help="base fee (msat) to set on the target->receiver channel; low => cheap jam")
    ap.add_argument("--receiver-prop-fee", type=int, default=0,
                    help="proportional fee (ppm) on the target->receiver channel; 0 keeps the "
                         "liquidity jam's entry buildable")
    ap.add_argument("--template-attack", default="SlowJam",
                    help="attack dir to clone attacktime_network.json/attacker.csv from if missing")
    args = ap.parse_args()

    attack_dir = args.network_dir / "attacks" / args.attack
    graph_path = attack_dir / "attacktime_network.json"

    # 1. Ensure the attack dir exists (clone the template attack's graph + attacker list).
    if not graph_path.exists():
        template_dir = args.network_dir / "attacks" / args.template_attack
        if not template_dir.exists():
            sys.exit(f"neither {attack_dir} nor template {template_dir} exists")
        attack_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(template_dir / "attacktime_network.json", graph_path)
        shutil.copy(template_dir / "attacker.csv", attack_dir / "attacker.csv")
        print(f"created {attack_dir} from template {args.template_attack}")

    doc = json.loads(graph_path.read_text())
    g = doc["sim_network"]
    aliases = alias_map(g)
    for a in (args.target_alias, args.sender_alias, args.receiver_alias):
        if a not in aliases:
            sys.exit(f"alias {a} not found in {graph_path}")

    # 2. Derive the peer (the channel_to_jam's endpoint that isn't the target).
    target_pk = aliases[args.target_alias]
    peer_alias = None
    for c in g:
        if c["scid"] == args.channel_to_jam_scid:
            for s in ("node_1", "node_2"):
                if c[s]["pubkey"] != target_pk:
                    peer_alias = c[s]["alias"]
    if peer_alias is None:
        sys.exit(f"channel-to-jam scid {args.channel_to_jam_scid} not found / not a target channel")

    # 3. Add attacker channels (idempotent): sender<->target (build) and sender<->peer (jam).
    next_scid = max(c["scid"] for c in g) + 1
    for honest in (args.target_alias, peer_alias):
        if channel_exists(g, args.sender_alias, honest):
            print(f"attacker channel {args.sender_alias}<->{honest} already present")
            continue
        g.append(synth_channel(next_scid, honest, aliases[honest],
                               args.sender_alias, aliases[args.sender_alias]))
        print(f"added attacker channel {args.sender_alias}<->{honest} (scid {next_scid})")
        next_scid += 1

    # 4. Set the target->receiver fee (base + proportional). The held protected HTLCs exit over this
    #    channel, so its fee drives the attacker's htlc_risk (hence the one-time entry cost). The
    #    proportional fee matters for the large liquidity-jam HTLCs; zeroing it keeps the liquidity
    #    jam's entry buildable. Denied revenue is unaffected (it comes from the jammed channel).
    set_fee = False
    for c in g:
        ends = {c["node_1"]["alias"], c["node_2"]["alias"]}
        if ends == {args.target_alias, args.receiver_alias}:
            for s in ("node_1", "node_2"):
                if c[s]["alias"] == args.target_alias:
                    if c[s]["base_fee"] != args.receiver_base_fee:
                        print(f"set {args.target_alias}->{args.receiver_alias} base_fee "
                              f"{c[s]['base_fee']} -> {args.receiver_base_fee}")
                    c[s]["base_fee"] = args.receiver_base_fee
                    c[s]["fee_rate_prop"] = args.receiver_prop_fee
                    set_fee = True
    if not set_fee:
        sys.exit(f"no {args.target_alias}<->{args.receiver_alias} channel to set the fee on "
                 f"(the receiver must already neighbour the target)")

    graph_path.write_text(json.dumps(doc, indent=1))
    print(f"experiment network ready: {graph_path} (target={args.target_alias}, peer={peer_alias})")


if __name__ == "__main__":
    main()
