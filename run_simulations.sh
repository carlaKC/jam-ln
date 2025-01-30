#!/bin/bash

# Define the different values to iterate over
reputation_values=(1000000 5000000 15000000)  # 1 USD, 5 USD, 15 USD
attacker_bootstrap_values=("30d" "90d" "165d")

# Loop through each combination of attacker-bootstrap and reputation-margin-msat
for attacker_bootstrap in "${attacker_bootstrap_values[@]}"; do
  for reputation_margin_msat in "${reputation_values[@]}"; do
    # Determine the USD value of the reputation margin for the results directory name
    if [[ $reputation_margin_msat -eq 1000000 ]]; then
      usd_value="1USD"
    elif [[ $reputation_margin_msat -eq 5000000 ]]; then
      usd_value="5USD"
    else
      usd_value="15USD"
    fi

    # Create the results directory based on attacker-bootstrap and USD value of reputation margin
    results_dir="results/ln50_${attacker_bootstrap}_${usd_value}"
    mkdir -p "$results_dir"

    # Run the cargo command in the background and redirect its output to logs.txt
    cargo run --package ln-simln-jamming \
      -- --attacker-bootstrap="$attacker_bootstrap" \
      --sim-file data/ln_50/simln_withattacker.json \
      --peacetime-file data/ln_50/no_attacker.csv \
      --bootstrap-file data/ln_50/with_attacker.csv \
      --target-reputation-percent=25 \
      --attacker-reputation-percent=25 \
      --clock-speedup 100 \
      --target-alias=22 \
      --attacker-alias=50 \
      --results-dir "$results_dir" \
      --reputation-margin-msat "$reputation_margin_msat" \
      >> "$results_dir/logs.txt" 2>&1 &

    echo "Started simulation for attacker-bootstrap=$attacker_bootstrap, reputation-margin-msat=$reputation_margin_msat. Logs are being written to $results_dir/logs.txt"
  done
done

# Wait for all background jobs to finish before exiting
wait
echo "All simulations completed."
