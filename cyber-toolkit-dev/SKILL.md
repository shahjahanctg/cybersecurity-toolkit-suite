---
name: cyber-toolkit-dev
description: "Build red and blue team security tools lawfully and safely."
version: 0.1.0
author: Hermes
platforms: [linux]
metadata:
  hermes:
    tags:
      - RedTeam
      - BlueTeam
      - SecurityToolkit
      - Tooling
      - Engineering
---

# Cybersecurity Toolkit Development — Red Team & Blue Team

This skill captures the engineering and operational discipline for building cybersecurity tools used by red teams (offensive assessment) and blue teams (defensive detection, response, and analysis). It covers tool categories, safe-and-lawful operating constraints, engineering quality for security tooling, data handling, testing under controlled conditions, and documentation that makes a tool usable by someone other than its author.

It does **not** provide exploit code, payload generation, target lists, active intrusion instructions, or anything that performs an attack against a system. It is about *building* tools, not *using* them against targets. Any hands-on work happens only in an environment you own or have explicit written authorization to test.

## When to Use

- Starting a new security tool project and needing a structure for it.
- Reviewing an existing security tool for engineering quality, safety, and operational fit.
- Teaching an AI agent the difference between a throwaway script and a maintainable security tool.
- Deciding which tool category a problem belongs to and what discipline that category carries.

## Prerequisites

- A controlled lab or environment you own (or have explicit written authorization to use) for any testing that touches running systems.
- Familiarity with the tool's intended team (red or blue) and the authorized use case.
- Awareness of the legal and organizational constraints that apply to the tool's use (scope, authorization, data handling, logging, retention).
- No external credentials are required to apply the skill's engineering guidance.

## How to Run

Load this skill at the start of a security tool build. Reference the relevant `references/` chapter when a specific concern arises (e.g. `skill_view(file_path="references/02-tool-categories.md")`).

## Quick Reference

| Concern | References File |
|---|---|
| Tool categories, red vs blue vs shared, operational mindset | `references/02-tool-categories.md` |
| Lawful/authorized use, scope, consent, data handling, logging, stop mechanisms | `references/03-lawful-operations.md` |
| Safe coding, input handling, privilege, sandboxing, error handling, auditability | `references/04-engineering-quality.md` |
| Testing in controlled labs, staging, destructive-test discipline, evidence capture | `references/05-testing-validation.md` |
| Structured data, formats, logging, evidence integrity, retention | `references/06-data-evidence.md` |
| Documentation, usage, output readability, reproducibility | `references/07-documentation.md` |
| Reporting craft — structure, audiences, findings, risk rating, evidence, remediation, framework context, lifecycle | `references/09-reporting.md` |
| Gap analysis — what this skill does not cover | `references/08-gap-analysis.md` |

## Procedure

1. **State the team and the authorized use case.** Red team tool, blue team tool, or shared infrastructure? What is it for, and under what authorization? Put this in the README before any code.
2. **Pick the tool category.** See `references/02-tool-categories.md`. The category shapes the engineering priorities (e.g. a detection rule engine cares about false positives and performance; an assessment helper cares about safety and auditability).
3. **Define the operational constraints up front.** Scope, authorization, data the tool touches, what it must not do, how it is stopped, how it is logged. See `references/03-lawful-operations.md`.
4. **Engineer for safety and auditability from the first line.** Input handling, privilege minimization, sandboxing where relevant, explicit error handling, and a trail of what the tool did. See `references/04-engineering-quality.md`.
5. **Test only in controlled environments.** Use a lab you own or are authorized to use. Stage the tool before any live use. Never test destructive behavior against anything you do not control. See `references/05-testing-validation.md`.
6. **Design the data and evidence story.** What does the tool emit, in what format, with what integrity and retention? See `references/06-data-evidence.md`.
7. **Document for the next operator.** Usage, output, prerequisites, limitations, and what the tool does *not* do. See `references/07-documentation.md`.
8. **End with a gap check.** See `references/08-gap-analysis.md` to confirm what the skill did not cover and whether a more specialized skill is needed.

## Pitfalls

- **Building a tool without stating the authorized use case.** A security tool without an authorization story is a liability, not an asset.
- **Treating safety as an afterthought.** A tool that can damage a system should be built so that damage is hard to trigger by accident and easy to stop on purpose.
- **Over-privileging the tool.** A tool that runs as root by default is a larger problem than the problem it solves.
- **No testing discipline.** Running untested security tooling against anything you do not fully control is how tools become incidents.
- **Unreadable output.** A tool whose output only its author understands is a one-person toy, not a team tool.
- **Data handling ignored.** Evidence and telemetry that are lost, tampered with, or retained inappropriately undermine the tool's value and create legal exposure.

## Verification

Before the tool is considered ready for any authorized use:

1. Is the authorized use case and scope written down and unambiguous?
2. Can the tool be stopped safely and predictably (explicit stop mechanism, not just "kill the process")?
3. Does the tool run with the minimum privilege appropriate to its function?
4. Has it been exercised only in a controlled environment you own or are authorized to use?
5. Is its output structured, readable, and reproducible by someone other than the author?
6. Is there a documented statement of what the tool does *not* do?

If any answer is "no," the tool is not ready.
