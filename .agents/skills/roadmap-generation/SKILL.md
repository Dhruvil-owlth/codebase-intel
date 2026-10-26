---
name: roadmap-generation
description: Build a dependency-aware, evidence-linked engineering backlog with explicit tests, rollback, completion criteria, and implementation boundaries.
---

# Roadmap generation

1. Start with baseline reproducibility, approved scope and rollback preparation.
2. Explain prioritization using severity, confidence, security, uncertainty and configured weights.
3. Give each task stable IDs, finding links, affected files, prerequisites and ordered changes.
4. Preserve safety-before-performance ordering and validate the task graph is acyclic.
5. Include tests, benchmark requirements, risks, rollback and checkable exit criteria for each task.
6. Leave unsupported phases empty rather than invent work. Require measurement before numeric targets.
7. Keep implementation preparation explicitly opt-in; preparation is not proof of implemented work.

See [the user guide](../../../docs/user-guide.md) for the preparation-only implementation command.
