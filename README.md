# Jamming Simulator

This simulator implements the following to mitigate channel jamming
attacks:
- Outgoing reputation:
  When forwarding a HTLC, the reputation of the *outgoing* channel is
  compared to the revenue that's been earned on the *incoming* channel.
- HTLC accountability: if a HTLC has occupied scarce resources, it
  will be forwarded as accountable to indicate to the receiving node
  that their reputation will be held accountable for its resolution.
- Resource bucketing: resources are divided into buckets
  - General: available to all channels, with some restrictions on how many
    resources a single peer can occupy.
  - Congestion: used when general resources are saturated, with strict
    control on access (because the node is likely under attack if general
    is full).
  - Protected: available to nodes with sufficient reputation.

A draft writeup of this scheme is available [here](https://github.com/carlaKC/lightning-rfc/pull/5).
The evolution of how we've been thinking about this problem is 
summarized [here](https://gist.github.com/carlaKC/5139adf4fd12b4ecd53c660b5be11bf0).

The simulator will execute a channel jamming attack against a target
node running the above proposed mitigation. It will exit when:
- The target's projected revenue in times of peace is less than its
  revenue under attack (in the simulation)
- The attack-specific shutdown condition has been met.
- The simulator has run out of peacetime forward to replay to compare
  revenue.

## Install

To install and run the simulator:
```
make install
ln-simln-jamming --network-dir {path to network directory}
```

## Tooling

To help set up custom networks for this simulator, the following tooling
is available:
* `forward-builder`: simulates payment traffic on a graph and records
  each node's forwarded HTLCs. This output is used to generate starting
  state reputation for all the nodes in the network, and to project
  what the target's revenue would be in times of peace (when not under
  attack).
* `reputation-builder`: creates a summary of each node in the network's
  starting reputation state, based on the output provided from
  `forward-builder`. Used to speed up simulation start times.

To install:
```
make install-tools
```

## Network Directory

To run the simulation, the following files are required in the directory
specified by the `--network` option:
* `peacetime_network.json`: the lightning network [graph](https://github.com/carlaKC/sim-ln?tab=readme-ov-file#advanced-usage---network-simulation)
  for the attack, with no attacker channels added.
* `attacktime_network.json`: the lightning network [graph](https://github.com/carlaKC/sim-ln?tab=readme-ov-file#advanced-usage---network-simulation)
  for the attack, with attacker channels added.
* `peacetime_traffic.csv`: a projected set of forwards for the 
  `peacetime_network.json` file, used to determine what the target's
  revenue would be in times of peace.
* `target.txt`: a text file containing the alias of the node being
  targeted for attack.
* `attacker.csv`: a csv file containing the alias of the attacking node.

Note: At present the simulation only supports a single attacker and
a single target node.

### Starting Reputation State

There are two options for setting up the starting reputation state for
the simulator:
1. Regular: start the simulator with reputations for honest nodes
   bootstrapped for 6 months, and attacking channels starting with
   no reputation.
2. Attacker bootstrap: start the simulator with reputation for honest
  nodes bootstrapped for 6 months, and attacking channels starting with
  reputation earned from passively forwarding payments in the network
  for a specified timestamp using `--attacker-bootstrap` 

For each mode of operation, the simulator requires that a reputation
summary is generated using the `reputation-builder` utility.
For each mode, the simulator requires the following files:
* `reputation_summary.csv`: a summary of each node's starting reputation
  state.
* `target_revenue.csv`: the target node's total revenue earned during
  this bootstrap period, expressed in msat.

These summaries may be generated using the `reputation-builder` utility.
If generating summaries for the case where an attacker is bootstrapping
their reputation passively, a `attacktime_traffic.csv` file will also
be required in the `network` directory (which can be generated using
the `forward-builder` utility)

## Shortcomings

- This simulator relies on [sim-ln](https://github.com/bitcoin-dev-project/sim-ln)
  to generate payment flows and projections, so traffic only represents
  our best guess at how payments flow in the network.
- Payments are generated with a fixed seed, but this is not perfectly
  deterministic in sim-ln.
