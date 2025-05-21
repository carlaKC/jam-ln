# Jamming Simulator

This simulator implements [outgoing reputation](https://gist.github.com/carlaKC/6762d88903d1cc27339859816ed80d43)
for a network of nodes and performs a [sink attack](https://delvingbitcoin.org/t/hybrid-jamming-mitigation-results-and-updates/1147#p-3212-manipulation-sink-attack-9)
against a target node in the network. In this attack, a malicious node
will:
- Open up channels and forward payments as usual to bootstrap its
  reputation with a target node.
- Slow jam the target's peers's general resources, so that all HTLCs
  must be accountable to reach the target.
- Hold any accountable HTLCs from the target with the goal of ruining its
  reputation with its peers.

## Requirements

To run the simulation you will need:
- `sim_file.json`: a json file describing the network that is being simulated,
  including channels that the attacking node has created to draw in 
  traffic. An example is available [here](https://github.com/carlaKC/attackathon/blob/master/data/ln_51_attacker/simln.json).
- `bootstrap.csv`: a csv containing projected forwards for the network
  *including*  that attacker's channels.
- `peacetime.csv`: a csv containing projected forwards for the network
  *excluding* the attacker's channels.

Projections are generated using [a sim-ln branch](https://github.com/carlaKC/sim-ln/tree/interceptor-latency)
that runs on a fully simulated network and outputs forwarding records
for each node in the network.

To run the simulator with the above files in the current directory:
```
make install
ln-simln-jamming --target-alias {alias string} --attacker-alias {alias string}
```

There are various ways that the simulator can be customized, see 
`cargo run -- --help` for details. A script is also provided to run
a set of simulations with different attacker bootstrap values in 
`./run_simulations.sh`.

## Attack Implementation

On startup, the simulator will use the `bootstrap-file` to set up 
reputation scores for the network:
- Honest nodes will have payments replayed for the full `reputation_window`
  that the simulator is configured with (default: 6 months, equal to
  `revenue-window-seconds reputation-multiplier`).
- The attacking node will have payments replayed for the 
  `attacker-bootstrap`, which must be <= `reputation_window`.

This sets up a starting point where the attacker has been peacefully
forwarding payments for the bootstrap period provided, and all honest
channels in the network have been around for at least the 
`reputation_window`.

The simulation will then start, implementing the attack as follows:
- General jamming the target's peers, so that only accountable HTLCs
  reach the target node.
- The attacking node will hold HTLCs for the maximum allowable period
  before risking a force close, then fail them back.

To compare revenue under attack, the forwards in the `peacetime.csv`
projection will be replayed as the simulation executes.

The simulation will shut down if:
- The target node's revenue in the simulation dips below its projected
  peacetime revenue (it has suffered revenue loss).
- The attacker no longer has reputation with the target (it can't
  continue its attack).
- The simulator has run out of peacetime forward to replay to compare
  revenue.

## Shortcomings

- This simulator relies on [sim-ln](https://github.com/bitcoin-dev-project/sim-ln)
  to generate payment flows and projections, so traffic only represents
  our best guess at how payments flow in the network.
- Payments are generated with a fixed seed, but this is not perfectly
  deterministic in sim-ln.
- The simulator implements "just in time" upgradable accountability, bumping up
  the accountability signal of a htlc only if it is required.
- At present the simulator only expects one channel between the target
  and attacking node.
