---
name: tool-categories
description: "Tool categories for red team, blue team, and shared security tooling."
---

# 02 — Tool Categories

## Core Mental Model

Every security tool serves a team, a function, and a data flow. Naming the category up front is not bureaucratic overhead — it tells you what "good" looks like for that tool. A packet analyzer is judged on accuracy and performance; an assessment helper is judged on safety, auditability, and clarity; a detection rule is judged on signal quality and false-positive rate.

## Tool Categories (by team and function)

### Red Team — Assessment & Simulation Tools

Tools that help an authorized red team simulate adversary behavior or assess a target environment during a planned engagement.

- **Recon and discovery helpers** — enumerate what is visible or accessible in scope (network surfaces, services, configurations). These are read-oriented; the engineering priority is accuracy and scope discipline.
- **Validation helpers** — confirm whether a condition exists (a misconfiguration, an exposed surface, a check result) without performing an attack. These answer "is X present?" not "break X."
- **Safe simulation aid tools** — tools that help simulate behavior patterns in a controlled, usually non-destructive way, within the authorized scope. The engineering priority is predictability, stop-ability, and auditability.
- **Reporting-oriented tools** — tools that structure findings for communication to the engagement owner.

Engineering emphasis for red-team tools: scope, consent, safety, auditability, and clarity of what the tool did.

### Blue Team — Detection, Analysis & Response Tools

Tools that help defenders observe, understand, detect, investigate, and respond.

- **Telemetry collectors / parsers** — ingest and normalize data (logs, flows, events, system data). Engineering priority: structured output, performance, handling volume and variety.
- **Detection rule engines / evaluators** — apply logic to data to surface signals. Engineering priority: signal quality, false-positive management, explainability, performance.
- **Investigation helpers** — tools that support triage and analysis (correlation, enrichment, timeline construction). Engineering priority: usability, reproducibility, clear provenance of data.
- **Response / orchestration helpers** — tools that support containment or remediation actions under authorization. Engineering priority: safety, authorization checks, audit trail, ability to undo or halt.
- **Visibility and reporting tools** — tools that present the state of the environment to defenders and stakeholders.

Engineering emphasis for blue-team tools: accuracy, performance at scale, signal quality, reproducibility, and safe action paths.

### Shared Infrastructure — Both Teams

- **Logging and evidence frameworks** — shared concerns for capturing, structuring, storing, and protecting telemetry and evidence.
- **Configuration and lab tooling** — tools for building and managing the controlled environments where tools are tested.
- **Utilities and libraries** — shared helpers (parsing, formatting, encryption, transport) used across categories.

## Cross-Cutting Concerns

These apply regardless of category:

- **Authorization and scope** are properties of the tool's use, not optional features.
- **Safety** matters for every tool — even read-oriented tools can cause problems at scale or against fragile systems.
- **Auditability** matters for every tool — a security tool should leave a trail of what it did, when, and by what authority.
- **Data handling** matters for every tool — what it reads, writes, stores, and transmits.

## Anti-Patterns

- **Category confusion.** Building a detection tool as if it were a scraper, or a reporting tool as if it were an action tool, leads to the wrong engineering priorities.
- **Action tools without stop mechanisms.** Any tool that can change state must be stoppable in a predictable way.
- **Read tools treated as harmless.** Reading at scale, or reading fragile systems, can itself cause problems.
- **One-person scripts passing as team tools.** If only the author can use it, it is not a team tool.

## Decision Rule

When starting a tool, answer four questions:

1. Which team is this for (red, blue, shared)?
2. What function does it serve (recon, validation, detection, analysis, response, reporting, infrastructure, utility)?
3. What is the authorized use case?
4. What are the safety and data-handling constraints?

The answers shape the engineering. Load `03-lawful-operations.md` next to make the authorization and safety constraints concrete.
