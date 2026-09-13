---
name: documentation
description: "Usage, output readability, prerequisites, limitations, and reproducibility for team tools."
---

# 07 — Documentation for Security Tools

## Core Mental Model

Documentation is what turns a script into a tool. A security tool whose only documentation is the author's memory is not a team asset. The documentation should let a competent operator — who is not the author — understand what the tool does, how to use it safely, what it outputs, and what it does *not* do.

## Minimal Documentation Set

Every security tool should have, at minimum:

- **What it does** — a plain-language description of the tool's function and intended use.
- **What it does NOT do** — explicit boundaries. This is as important as what it does.
- **Authorized use context** — the team, the kind of environment, the kind of scope for which the tool is intended.
- **Prerequisites** — what must be in place before the tool is used (environment, permissions, dependencies, data, authorization).
- **Usage** — how to invoke the tool, what the main inputs/options are, and what reasonable invocations look like.
- **Output** — what the tool produces, in what form, and how to read it.
- **Safety notes** — what can go wrong, what the tool can affect, how to stop it, and what to do if something unexpected happens.
- **Limitations** — where the tool is weak, approximate, or not suitable.
- **Version** — the tool should carry a version so its behavior can be attributed and reproduced.

## Output Readability

- The output should be readable by its intended consumer, not only by the author.
- If the output is machine-consumed, document the schema or format.
- If the output is human-consumed, document what each part means.
- If the output has security significance, document how to interpret it and what not to conclude from it.
- Provide examples — a worked example is often worth more than a long description.

## Reproducibility

- Document the environment and version the tool was built and tested against.
- Document the inputs needed to reproduce a given output.
- Document known non-determinism and its sources, if any.
- A tool that cannot be reproduced is a tool whose results cannot be trusted or reviewed.

## Usage Guidance & Guardrails

- Show the safe path, not only the possible path. A tool can do many things; the documentation should make the authorized, safe usage clear.
- Document the stop mechanism and how to recover from common problems.
- Where relevant, document the scope checks or authorization steps the operator must perform.
- Warn about the dangerous paths explicitly, not implicitly.

## Living Documentation

- Documentation should travel with the tool and be updated when the tool changes.
- A tool and its documentation should be versioned together enough that you can tell which docs belong to which tool version.
- Outdated documentation is worse than no documentation in some cases — it misleads. Keep it current or mark it as such.

## Anti-Patterns

- **No README.** The tool lives in the author's head and dies with the author's attention.
- **Usage shown, safety omitted.** Tells the operator how to run the tool, not what to watch for.
- **Output undocumented.** The operator gets data they cannot interpret.
- **Documentation never updated.** Drifts from the tool until it is misleading.
- **Only the author can use it.** If that is true, it is not a team tool.

## Decision Rule

Before sharing the tool beyond its author:

1. Can a competent operator understand what the tool does and does not do from the docs?
2. Can they invoke it safely, with the right prerequisites?
3. Can they interpret the output?
4. Do they know how to stop it and what to do if it misbehaves?
5. Is the version and the environment clear enough to reproduce?

If any answer is "no," finish the documentation before the tool leaves the author's private workspace.

## When to Load More

Load `08-gap-analysis.md` to check what this skill did not cover and whether the tool needs a more specialized lens.
