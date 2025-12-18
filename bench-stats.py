#!/usr/bin/env python3
import re
import sys
import statistics

def parse_benchmarks(filename):
    """Parse benchmark results and group by trace name."""
    data = {}
    
    with open(filename) as f:
        for line in f:
            # Match: BenchmarkSafroleTraces/trace.bin-8   100   12345678 ns/op
            match = re.match(r'Benchmark\w+/([^\s-]+).*?(\d+\.?\d*)\s+ns/op', line)
            if match:
                trace_name = match.group(1)
                ns_per_op = float(match.group(2))
                
                if trace_name not in data:
                    data[trace_name] = []
                data[trace_name].append(ns_per_op)
    
    return data

def calculate_stats(data):
    """Calculate statistics across all runs."""
    all_values = []
    trace_values = {}
    
    for trace, values in data.items():
        all_values.extend(values)
        avg = statistics.mean(values)
        trace_values[trace] = avg
    
    all_values.sort()
    
    def percentile(data, p):
        idx = int(len(data) * p / 100)
        return data[min(idx, len(data)-1)]
    
    min_val = min(all_values)
    max_val = max(all_values)
    
    # Find which trace had min/max
    min_trace = min(trace_values, key=trace_values.get)
    max_trace = max(trace_values, key=trace_values.get)
    
    print(f"Statistics across {len(all_values)} total runs:")
    print(f"  Min: {min_val/1e6:.3f} ms (trace: {min_trace})")
    print(f"  P50: {percentile(all_values, 50)/1e6:.3f} ms")
    print(f"  P95: {percentile(all_values, 95)/1e6:.3f} ms")
    print(f"  P99: {percentile(all_values, 99)/1e6:.3f} ms")
    print(f"  Max: {max_val/1e6:.3f} ms (trace: {max_trace})")
    print(f"\nPer-trace averages:")
    for trace in sorted(trace_values.keys()):
        print(f"  {trace}: {trace_values[trace]/1e6:.3f} ms")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: bench-stats.py <benchmark-results.txt>")
        sys.exit(1)
    
    data = parse_benchmarks(sys.argv[1])
    if not data:
        print("No benchmark data found")
        sys.exit(1)
    
    calculate_stats(data)
