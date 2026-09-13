---
name: lawful-operations
description: "Lawful use, authorization, scope, consent, data handling, logging, and stop mechanisms."
---

# 03 — Lawful & Authorized Operations

## Core Mental Model

A security tool is only legitimate when its use is authorized and within scope. This section is not about avoiding work — it is about making the authorization story explicit so the tool is usable by a team rather than a liability carried by its author. The authorization story belongs in the tool's documentation and, where relevant, in its code (e.g. a built-in scope check, a required authorization flag, a logging statement of authority).

## The Authorization Story

Every tool should be able to answer:

- **Who is authorized to use this tool?** (role, team, engagement, environment)
- **What is it authorized to do?** (the permitted actions and the in-scope targets/systems)
- **What is it NOT authorized to do?** (out of scope, prohibited actions)
- **Under what conditions may it be used?** (environment, timing, preconditions, approvals)
- **How is its use logged and attributable?** (who ran it, when, against what, with what result)

A tool that cannot answer these questions is not ready for authorized use.

## Scope Discipline

- Define scope before the tool is used, not after.
- Scope can be narrow (a single host, a single service, a defined time window) or broad (an environment, a program, a class of systems) — but it must be defined.
- A tool built for a narrow scope should not be casually repurposed for a broader one without re-validating authorization and safety.
- Out-of-scope behavior should be hard to trigger by accident and obvious when it is attempted.

## Consent & Authorization Models

Different contexts call for different models:

- **Owned environment** — you own the system; authorization is internal but still worth documenting (who may use the tool, under what conditions).
- **Engagement-based** — a planned engagement with an agreed scope, rules of engagement, and an authorized owner. The tool should align with the documented engagement terms.
- **Defensive use** — blue-team tooling used on systems the team is authorized to defend. Authorization is still worth documenting, especially for tools that take action.
- **Research / lab use** — use confined to a lab you control. The lab is the scope.

## Data Handling

Security tools often touch sensitive data: system state, logs, network data, credentials, personal data, organizational data.

- **Minimize what the tool touches** to what it needs.
- **Classify the data** the tool reads or writes (public, internal, sensitive, restricted).
- **Protect data in transit and at rest** where the classification requires it.
- **Do not collect more than needed** for the tool's function.
- **Know the retention requirement** — how long is the output kept, by whom, and under what access control?
- **Be aware of privacy and legal constraints** on personal data, regardless of team.

## Logging & Auditability

A security tool should leave a trail:

- **What was run** (tool, version, invocation, parameters)
- **By whom** (attribution where appropriate)
- **When** (timestamp, timezone)
- **Against what** (scope, target identifiers within scope)
- **With what result** (outcome, findings, errors, stop conditions)

Logging should be sufficient to reconstruct what happened without being so verbose that it becomes unusable or so detailed that it captures more than necessary.

## Stop Mechanisms & Safety Controls

- Every tool that can affect state should have an explicit, predictable way to stop.
- The stop mechanism should be designed, not improvised (not only "kill the process").
- Consider what happens when the tool is interrupted mid-operation — partial state, cleanup, rollback where relevant.
- For tools used in engagements or production, a kill-switch or pause mechanism is often appropriate.
- Design so that accidental misuse is hard and intentional misuse is detectable.

## Operational Hygiene

- Use the tool only where authorized.
- Do not share tools, outputs, or findings outside the authorized audience without checking whether that is permitted.
- Keep version control over the tool itself — an unversioned tool is hard to attribute, reproduce, or safely update.
- Keep the operating instructions with the tool — a tool without usage guidance is a latent incident.

## Decision Rule

Before a tool is used in any setting beyond the author's own private lab:

1. Is the authorization documented (who, what, under what conditions)?
2. Is the scope defined and bounded?
3. Does the tool log enough to attribute and reconstruct its use?
4. Does the tool have a predictable stop mechanism?
5. Has the data the tool touches been classified and handled appropriately?

If any answer is "no," the tool stays in the author's private lab until it is "yes."

## When to Load More

Load `04-engineering-quality.md` to translate these operational constraints into concrete engineering choices.
