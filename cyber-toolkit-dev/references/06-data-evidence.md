---
name: data-evidence
description: "Structured data, formats, logging, evidence integrity, and retention for security tools."
---

# 06 — Data & Evidence

## Core Mental Model

Security tools live or die on the data they produce and the data they touch. For blue-team tools, data quality and integrity are the product. For red-team tools, data is the record of the authorized operation and the basis for reporting. Either way, the tool should emit structured, attributable, integrity-aware data, and it should handle that data with the care its classification requires.

## Output Design

- **Prefer structured output** (JSON, CSV, a defined schema, a defined log format) over free-text where the tool's output will be consumed by other tools or people.
- **Structured does not mean verbose.** Emit what is useful; do not pad the output with noise.
- **Define the schema** — what fields exist, what they mean, what types they are, what "missing" means.
- **Make output reproducible** — given the same input and the same tool version, the output should be predictable enough to reason about.

## Log Design

- Logs should support reconstruction: what ran, when, by what invocation, against what scope, with what outcome.
- Logs should be structured enough to be searched and correlated, not just read by a human.
- Log levels matter: distinguish diagnostic detail from operational events from security-relevant events.
- Do not log sensitive data unless the tool's function requires it and the logging is itself appropriately protected.

## Evidence Integrity

When the tool's output is evidence (findings, test results, captured data):

- **Know the provenance** — where did this piece of data come from, when, and by what process?
- **Protect integrity** where needed — append-only storage, hashing, signing, or other integrity mechanisms appropriate to the stakes.
- **Avoid silent modification** — the data should not be changed by the tool after capture without the change being visible and attributable.
- **Preserve context** — a finding without its context (what was scanned, when, with what version, under what scope) is much less useful.

## Data Classification & Handling

- Classify the data the tool reads and writes (e.g. public, internal, sensitive, restricted).
- Handle each class appropriately: minimize collection, protect in transit and at rest where required, restrict access, and apply the right retention.
- Be especially careful with: personal data, credentials, sensitive system data, and any data whose mishandling has legal or organizational consequences.
- If the tool handles personal data, treat privacy as a design constraint, not a compliance footnote.

## Retention

- Decide, for each output type, how long it is kept, by whom, and under what access control.
- Retain what is needed for the tool's purpose and any required reporting or evidence; do not retain everything forever by default.
- Have a deletion or archival path for data that has passed its useful life.
- Document the retention decision where it matters.

## Sharing & Distribution

- Know who is authorized to receive the tool's output.
- Outputs can be sensitive even when the tool is benign — a scan result, a detection event, a log excerpt can reveal a lot.
- Share through controlled channels, not by default.
- Be careful about what is included in a shared artifact (metadata, paths, identifiers, internal names).

## Anti-Patterns

- **Unstructured free-text as the only output.** Works for a one-off glance, fails as a team tool.
- **Evidence with no provenance.** A result with no context is a rumor.
- **Logging sensitive data by accident.** Diagnostic logging is still data handling.
- **Retaining everything forever.** This is not diligence; it is accumulation of liability.
- **Sharing outputs without checking authorization.** The tool's output may be more sensitive than the tool itself.

## Decision Rule

For each output the tool produces, ask:

1. Is it structured enough to be consumed beyond a glance?
2. Does it carry enough context to be understood later?
3. Is its integrity protected where the stakes require it?
4. Is the data class known and handled appropriately?
5. Is there a retention and deletion decision, not just accumulation?

If any answer is weak, the data story needs work before the tool is shared or used beyond a private lab.

## When to Load More

Load `07-documentation.md` to make the tool usable by someone other than its author.
