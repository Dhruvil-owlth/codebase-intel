---
name: logic-optimization
description: Evaluate algorithm and data-structure changes against actual semantics, workload evidence, maintainability, and regression risk.
---

# Logic optimization

1. Retrieve the complete affected symbol and its source/test relationships.
2. Explain current approach, source evidence and computational assumptions.
3. Compare an incremental change with retaining the existing implementation.
4. Preserve duplicate handling, ordering, equality, error behavior and caller contracts.
5. Define tests for boundary values and representative size-dependent measurements.
6. Schedule only evidence-backed work after relevant correctness and security prerequisites.

Do not recommend clever code or a new technology solely for novelty. See [architecture](../../../docs/architecture.md) for current planner limits.
