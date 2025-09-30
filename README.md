# Jamming Simulator

This simulator implements the reputation and accountability scheme
proposed [here](https://github.com/lightning/bolts/pull/1280), which
is the first part of a [hybrid proposal](https://gist.github.com/carlaKC/02251cd061260bbb149f361c65fc9f2f)
to address channel jamming attacks.

This simulator will run two networks in parallel:
* Peacetime: propagate payments through the network without the attacker
  present (no channels, no attack), representing peacetime operation of
  the network.
* Attacktime: propagate payments through the network with the attacker's
  channels added and its attack running.

Once the attack is completed, it will report on the target node's
revenue in each network, along with reputation statistics from the
attack time network.

## Considerations

There are two features of this proposal that have *not been 
implemented* yet:
- [ ] Scale `opportunity_cost` as a float, [rather than an integer](https://github.com/lightning/bolts/pull/1280#discussion_r2349880197).
- [ ] [Do not allow overpayment](https://github.com/lightning/bolts/pull/1280#discussion_r2369501671) of advertised fees.

Please also note that this solution is intended to be deployed with
an unconditional fee (charged on failed payments) of 1% of the success
case fees. This should be considered when assessing the cost of an
attack.

## Setting Up a Network

The `networks` directory contains graphs that can be used to execute
attacks against. Each sub-directory is contains the following:
* `peacetime_network.json`: the lightning network [graph](https://github.com/carlaKC/sim-ln?tab=readme-ov-file#advanced-usage---network-simulation)
  for the attack, with no attacker channels added.
* `peacetime_traffic.csv`: projected traffic for this network in times
  of peace, used to execute peacetime operation of the network.
* `reputation.csv`: the starting state reputation for nodes in the
  network, which bootstraps network state with 6 months of reputation
  history.
* `target.txt`: a text file containing the alias of the node being
  targeted for attack.

To create an attack against a peacetime network, you will need to
provide the following files in 
`networks/{network name}/attacks/{attack name}`: 
* `attacktime_network.json`: the `peacetime_network.json` with any
  attacker channels required added to it. Note that these graphs
  *must* be identical *except* for the attacker's channels.
* `attacker.csv`: a csv file containing the alias of the attacking 
  node(s).

For more complex network setups see:
- [Changing target node](#changing-target-node): to change the node
  that is attacked in a graph.
- [Bootstrapping attacker reputation](#bootstrapping-attacker-reputation):
  for attacks where the attacker passively forwards payments in the
  network to build reputation before starting an attack.
- [Creating your own network](#creating-your-own-network): for
  instructions on setting up your own peacetime network.

## Writing an Attack

To implement an attack in the simulator, you need to:
* Implement the `JammingAttack` trait.
* Add your attack to the `AttackType` enum.

See the docs on each for further instructions.

## Install

To install and run the simulator:
```
make install
ln-simln-jamming --network-dir {path to network directory} --attack {attack name}
```

Output produced by the simulator will be written to:
`results/{network name}/{attack name}/start_timestamp_seconds`

## Advanced Network Setup

To install tooling required for advanced network setup:
```
make install-tools
```

### Changing Target Node

In our simulator, the target node is a routing node (it does not send
or receive payments). This means that peacetime traffic must be updated
if you want to change the target node.

* Update the alias in `target.txt` to the new target node.
* Run the following to regenerate peacetime projections:

```
forward-builder --network-dir {network name}
reputation-builder --network-dir {network name}
```

This will recreate `peacetime_traffic.csv` and `reputation.csv` with
your updated target node.

### Bootstrapping Attacker Reputation

If you would like to run an attack which requires the attacker passively
forwarding payments for a long period of time, you can speed this process
up by providing an attacker bootstrap file.

Generate projected forwards for the network *including* the attacker's
channels:
```
forward-builder --traffic-type attacktime --network-dir {path to network directory} --attack {attack name} 
```

Build reputation summaries for the "bootstrap duration" that you would
like the attacker to passively forward payments in the network for.
```
reputation-builder --network-dir {path to network directory} --attack {attack name} --attacker-bootstrap {bootstrap duration}
```

When you run the simulator, include the `--attacker-bootstrap` option
with the same value as used for `reputation-builder`. This will run
the simulator with the attacker's reputation bootstrapped for the
period provided.

### Creating Your Own Network

If you'd like to create your own `peacetime_graph.json`, you can
manually create your own graph or use [this script](https://github.com/carlaKC/sim-ln/blob/script-lnd-to-simln/tools/lnd_to_simln.py)
to convert the output of LND's `describegraph` call to the correct
format.

Once you have this graph, run the following in sequence to generate
`peacetime_traffic.csv` and `reputation.csv` respectively:
```
forward-builder --network-dir {path to network directory}
reputation-builder --network-dir {path to network directory}
```

## Shortcomings

- This simulator relies on [sim-ln](https://github.com/bitcoin-dev-project/sim-ln)
  to generate payment flows and projections, so traffic only represents
  our best guess at how payments flow in the network.
- Payments are generated with a fixed seed, but this is not perfectly
  deterministic in sim-ln.
