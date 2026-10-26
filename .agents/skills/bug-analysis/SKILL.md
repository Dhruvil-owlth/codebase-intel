---
name: bug-analysis
description: Review source-backed correctness candidates, distinguish static support from reproduced defects, and define focused regression tests.
---

# Bug analysis

1. Revalidate the cited source hash and accurate line range.
2. Inspect the surrounding symbol and reachable callers using targeted retrieval.
3. Identify assumptions about shadowed identifiers, types, intentional sentinels and business invariants.
4. Use SUPPORTED for defensible static evidence, HYPOTHESIS for uncertain impact, and VERIFIED only after successful direct validation.
5. Specify boundary, normal and failure-path regression tests; do not run target scripts without separate authorization.
6. Record the smallest compatible correction, alternatives, rollback and remaining uncertainty in the canonical finding.

See [the user guide](../../../docs/user-guide.md) for classifications. Default analysis does not change application code.
