import sys
import os
import json
import csv

def normalize_alias(alias):
    try:
        return str(int(alias.strip()))
    except:
        return None

def extract_unique_nodes(sim_network):
    nodes = {}
    for chan in sim_network:
        for node_key in ['node_1', 'node_2']:
            node = chan[node_key]
            pubkey = node['pubkey']
            if pubkey not in nodes:
                nodes[pubkey] = {
                    'alias': normalize_alias(node['alias']),
                    'pubkey': pubkey
                }
    return nodes

def find_target_pubkey(nodes_dict, target_alias):
    for pubkey, node in nodes_dict.items():
        if normalize_alias(node['alias']) == target_alias:
            return pubkey
    return None

def candidate_nodes(sim_network, target_pubkey):
    node_capacity = {}
    connected_to_target = set()

    for chan in sim_network:
        n1 = chan['node_1']['pubkey']
        n2 = chan['node_2']['pubkey']
        capacity = int(chan['capacity_msat'])

        for n in [n1, n2]:
            node_capacity[n] = node_capacity.get(n, 0) + capacity

        if target_pubkey in (n1, n2):
            connected_to_target.add(n1)
            connected_to_target.add(n2)

    candidates = [n for n in node_capacity if n not in connected_to_target]
    return sorted(candidates, key=lambda n: node_capacity[n], reverse=True)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python add_attacking_node.py /path/to/network_directory")
        sys.exit(1)

    network_dir = sys.argv[1]
    peacetime_path = os.path.join(network_dir, "peacetime_network.json")
    attacktime_path = os.path.join(network_dir, "attacktime_network.json")
    attacker_csv_path = os.path.join(network_dir, "attacker.csv")
    target_path = os.path.join(network_dir, "target.txt")

    if not os.path.exists(peacetime_path):
        print(f"Missing: {peacetime_path}")
        sys.exit(1)

    if not os.path.exists(target_path):
        print(f"Missing: {target_path}")
        sys.exit(1)

    with open(target_path, 'r') as f:
        target_alias = normalize_alias(f.read())

    with open(peacetime_path, 'r') as f:
        graph = json.load(f)

    sim_network = graph.get("sim_network", [])
    if not sim_network:
        print("No channels found in peacetime_network.json")
        sys.exit(1)

    nodes = extract_unique_nodes(sim_network)

    # Determine the target's pubkey
    target_pubkey = find_target_pubkey(nodes, target_alias)
    if not target_pubkey:
        print(f"No node with alias '{target_alias}' found.")
        sys.exit(1)

    # Determine new attacker alias
    aliases = [int(alias) for alias in [n['alias'] for n in nodes.values()] if alias and alias.isdigit()]
    attacker_alias = str(max(aliases) + 1 if aliases else 1)
    attacker_pubkey = "035a43121d24b2ff465e85af9c07963701f259b5ce4ee636e3aeb503cc64142c11"

    # Save attacker info
    with open(attacker_csv_path, 'w', newline='') as f:
        f.write(attacker_alias)

    # Select candidates
    candidates = candidate_nodes(sim_network, target_pubkey)
    channel_count = int(len(nodes) * 0.1)
    channel_capacity_msat = 10_000_000
    new_channels = []

    def make_node(pubkey, alias, is_attacker=False):
        return {
            "pubkey": pubkey,
            "alias": alias,
            "max_htlc_count": 100,
            "max_in_flight_msat": channel_capacity_msat,
            "min_htlc_size_msat": 1000,
            "max_htlc_size_msat": channel_capacity_msat - 5000,
            "cltv_expiry_delta": 40 if is_attacker else 144,
            "base_fee": 0 if is_attacker else 1000,
            "fee_rate_prop": 0 if is_attacker else 1000
        }

    # Connect attacker to candidate nodes
    for i in range(channel_count):
        chan = {
            "scid": 10_000_000 + i,
            "capacity_msat": channel_capacity_msat,
            "node_1": make_node(attacker_pubkey, attacker_alias, is_attacker=True),
            "node_2": make_node(candidates[i], nodes[candidates[i]]['alias'], is_attacker=False),
        }
        new_channels.append(chan)

    # Connect attacker directly to the target node
    chan = {
        "scid": 9_999_999,
        "capacity_msat": channel_capacity_msat * channel_count,
        "node_1": make_node(attacker_pubkey, attacker_alias, is_attacker=True),
        "node_2": make_node(target_pubkey, target_alias, is_attacker=False),
    }
    new_channels.append(chan)

    # Combine with original network and write output
    graph["sim_network"] = new_channels + sim_network
    with open(attacktime_path, 'w') as f:
        json.dump(graph, f, indent=2)

    print(f"Added attacker {attacker_alias} to network. Wrote output to {attacktime_path}")
