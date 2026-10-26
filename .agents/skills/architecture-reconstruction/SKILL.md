---
name: architecture-reconstruction
description: Reconstruct supported repository structure from indexed modules and imports while separating graph facts from runtime architecture hypotheses.
---

# Architecture reconstruction

Start from an existing audit index and its coverage limitations.

1. Inspect manifest-based ownership, entry-point candidates and resolved local imports.
2. Retrieve exact definitions and related files for any claimed boundary.
3. Treat import cycles as structural evidence; investigate initialization and ownership consequences before recommending extraction.
4. Generate Mermaid with stable safe identifiers and link labels back to actual paths.
5. Mark service, data, state and runtime flow claims as unverified unless independent evidence exists.

See [architecture](../../../docs/architecture.md) and [support boundaries](../../../docs/support.md). Do not infer complete business architecture from names alone.
