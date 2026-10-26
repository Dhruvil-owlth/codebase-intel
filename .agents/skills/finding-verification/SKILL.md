---
name: finding-verification
description: Validate finding schemas, source hashes and ranges, links, classifications, references, and roadmap dependencies before delivery.
---

# Finding verification

1. Run the CLI validate command for the selected persisted run.
2. Check required fields, unique IDs and confidence/classification consistency.
3. Re-read evidence files and verify their hashes, line bounds and redacted snippets.
4. Validate Markdown links, stable finding references and task prerequisites; reject dependency cycles.
5. Review partial coverage, parser failures, model errors and unresolved evidence.
6. Do not promote static or model suggestions to VERIFIED without a successful direct validation result.
7. Report remaining failures accurately; a clean document schema does not prove runtime correctness.

See [the user guide](../../../docs/user-guide.md) for commands and [support boundaries](../../../docs/support.md) for the meaning of verification.
