---
name: performance-analysis
description: Investigate bounded static performance candidates and require representative measurement before recommending targets or claiming gains.
---

# Performance analysis

1. Inspect the exact loop, lookup, data structure and caller context.
2. Separate static structure from runtime type, size, frequency and allocation assumptions.
3. Require representative workload, runtime versions, warm-up policy, sample count and variability before setting a target.
4. Balance latency, memory, ordering, equality semantics, readability and maintenance cost.
5. Preserve correctness and security tests before implementing a performance change.
6. Record a baseline and before/after evidence only when an approved measurement actually ran.

No profiling or target benchmark runs by default. See [support boundaries](../../../docs/support.md) and the generated benchmark-baseline report.
