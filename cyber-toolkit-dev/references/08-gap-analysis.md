---
name: gap-analysis
description: "What this skill does not cover and when to seek a more specialized skill."
---

# 08 — Gap Analysis: What This Skill Does Not Cover

## What This Skill Covers

This skill is about the engineering and operational discipline for *building* red-team and blue-team security tools lawfully, safely, and in a way that makes them usable by a team. It covers:

- Tool categories and the mindset that goes with each.
- Authorization, scope, consent, data handling, logging, and stop mechanisms.
- Engineering quality: input handling, privilege minimization, safety, error handling, auditability, dependencies.
- Testing in controlled environments, including destructive-test discipline.
- Data and evidence: structured output, integrity, classification, retention, sharing.
- Documentation that makes a tool usable by someone other than its author.

## What This Skill Does Not Cover

- **Specific exploitation techniques or payloads.** This skill is about building tools, not about techniques or intrusions.
- **Active attack instructions against real targets.** Any such activity is out of scope and must only happen within an authorized engagement or a controlled lab you own.
- **A catalog of every security tool type.** The categories here are a starting framework, not an exhaustive taxonomy.
- **Organization-specific policy, compliance, or legal advice.** Apply your organization's rules and any applicable law; this skill gives engineering discipline, not legal counsel.
- **Operational runbooks for a specific team or engagement.** Those are context-specific and belong with the team and engagement, not in a general skill.
- **Deep specialization for any one tool class** (e.g. a full guide to building a detection engine, a full guide to network protocol analysis, a full guide to forensic artifact handling). Where a tool needs deep specialization, that is a candidate for a focused skill.

## When to Build a More Specialized Skill

Consider a focused skill when the tool class has its own deep engineering concerns that this skill only touches lightly:

- **Detection engineering** — rule design, signal quality, false-positive management, detection testing, telemetry coverage.
- **Network protocol analysis tooling** — packet handling, protocol parsing, performance at wire speed, replay and fuzzing in a lab.
- **Forensic artifact tooling** — acquisition integrity, chain of custody, artifact reliability, preservation.
- **Automation/orchestration for response** — approval flows, safety, idempotency, rollback, integration with existing systems.
- **Lab and environment tooling** — building controlled environments, image management, isolation, reset/restore.

A specialized skill should be narrower and deeper than this one, and should still carry the lawful-and-safe orientation established here.

## The Persistent Rule

No matter how specialized the tool or how deep the skill, one rule does not go away:

A security tool is built for an authorized use, in a controlled environment for testing, with safety and auditability engineered in from the start, and with documentation that lets someone other than the author use it responsibly. If any of those is missing, the tool is not ready.
