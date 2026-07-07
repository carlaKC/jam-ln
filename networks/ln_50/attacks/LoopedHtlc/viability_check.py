#!/usr/bin/env python3
"""Exhaustive check that no (entry, mid) peer pair admits an accountable loop through the
target on ln_50. See sim-findings.md section 5. Run from networks/ln_50/."""
import csv, json

TARGET = "03d607f3e69fd032524a867b288216bfab263b6eaee4e07783799a6fe69bb84fac"
# Opportunity-cost multiplier ~ (cltv_hold / resolution_period - 1) for the loop's accumulated
# CLTV (~222 blocks, i.e. ~222*600s held vs a 90s resolution period). A hop must have at least
# base_fee * RISK_MULT reputation on its outgoing channel to relay the accountable HTLC.
RISK_MULT = 1479


def main():
    net = json.load(open("peacetime_network.json"))["sim_network"]
    rep = {}
    for row in csv.DictReader(open("reputation.csv")):
        rep.setdefault(row["pubkey"], {})[row["scid"]] = (
            int(row["outgoing_reputation"]),
            int(row["incoming_revenue"]),
        )

    peers = {}
    for c in net:
        n1, n2 = c["node_1"], c["node_2"]
        if TARGET in (n1["pubkey"], n2["pubkey"]):
            peer = n2 if n1["pubkey"] == TARGET else n1
            scid = str(c["scid"])
            t_out, t_inrev = rep.get(TARGET, {}).get(scid, (0, 0))  # target->peer out_rep / revenue
            p_out, _ = rep.get(peer["pubkey"], {}).get(scid, (0, 0))  # peer->target out_rep
            peers[peer["alias"]] = dict(
                t_out=t_out, t_inrev=t_inrev, p_out=p_out, base=peer["base_fee"]
            )

    viable = 0
    for e, ev in peers.items():
        entry_ok = ev["p_out"] > ev["base"] * RISK_MULT  # entry relays accountable IN
        for m, mv in peers.items():
            if m == e:
                continue
            first_ok = mv["t_out"] > ev["t_inrev"]  # target->mid out_rep clears entry revenue
            return_ok = mv["p_out"] > mv["base"] * RISK_MULT  # mid relays accountable back
            if entry_ok and first_ok and return_ok:
                viable += 1
                print(f"VIABLE entry={e} mid={m}")
    print(f"viable (entry, mid) pairs: {viable}")


if __name__ == "__main__":
    main()
