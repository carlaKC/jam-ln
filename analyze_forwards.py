#!/usr/bin/env python3
"""
Script to analyze Lightning Network forward data by channel_out_id.
"""

import csv
import sys
from collections import defaultdict

def analyze_forwards_by_channel(file_path: str):
    """Analyze forward data by channel_out_id."""
    
    # Data storage: channel_out_id -> {'total_amount': int, 'count': int}
    channel_stats = defaultdict(lambda: {'total_amount': 0, 'count': 0})
    
    # Read CSV data
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                outgoing_amt = int(row['outgoing_amt'])
                channel_out = row['channel_out_id']
                
                channel_stats[channel_out]['total_amount'] += outgoing_amt
                channel_stats[channel_out]['count'] += 1
                
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    if not channel_stats:
        print("No data found in file")
        return
    
    print("Channel Out ID Analysis")
    print("=" * 60)
    print(f"{'Channel ID':<15} {'Total Sent (msat)':<20} {'Count':<10} {'Avg per Forward':<15}")
    print("-" * 60)
    
    # Sort by total amount descending
    for channel_id, stats in sorted(channel_stats.items(), 
                                   key=lambda x: x[1]['total_amount'], 
                                   reverse=True):
        total = stats['total_amount']
        count = stats['count']
        avg = total / count if count > 0 else 0
        
        print(f"{channel_id:<15} {total:>19,} {count:>9} {avg:>14,.0f}")
    
    # Summary
    total_forwards = sum(stats['count'] for stats in channel_stats.values())
    total_amount = sum(stats['total_amount'] for stats in channel_stats.values())
    
    print("-" * 60)
    print(f"{'TOTAL':<15} {total_amount:>19,} {total_forwards:>9} {total_amount/total_forwards:>14,.0f}")
    print(f"\nUnique channels: {len(channel_stats)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_forwards.py <csv_file>")
        sys.exit(1)
    
    analyze_forwards_by_channel(sys.argv[1])