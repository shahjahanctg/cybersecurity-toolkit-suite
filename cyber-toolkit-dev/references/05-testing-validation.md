---
name: testing-validation
description: "Controlled-lab testing, staging, destructive-test discipline, evidence capture."
---

# 05 — Testing & Validation in Controlled Environments

## Core Mental Model

Security tools must be tested, and they must be tested safely. The right place to test is a controlled environment you own or are explicitly authorized to use. Testing against anything you do not control is how a tool becomes an incident. The discipline here is simple: bound the test, know what the tool is allowed to touch, and capture evidence of the test.

## Testing Environments

- **Private lab** — the default testing ground. Systems you control, isolated enough that mistakes stay contained.
- **Authorized test environment** — a test environment you are permitted to use for this tool, with documented scope.
- **Staging / pre-live** — a closer approximation of the real environment, still within authorization, used before any live-authorized use.
- **Production** — the live environment. A security tool should not be first exercised here. If it must be, that is a deliberate, authorized, supervised decision, not normal testing.

## What to Test

- **Correctness** — does the tool do what it claims, on the inputs it claims to handle?
- **Safety** — what happens on misuse, on unexpected input, on interruption, on failure? Can it be stopped?
- **Boundaries** — does the tool stay within its scope? What happens at and beyond the boundary?
- **Performance** — does it handle the volume, rate, or size it will face? For blue-team tools, this is often central; for red-team tools, it matters for predictability.
- **Auditability** — does the tool produce the log/output you expect, in the form you expect?
- **Destructive behavior (if any)** — only in a lab you control, with a clear plan for what "destructive" means and how to recover.

## Destructive-Test Discipline

If the tool can destroy, disrupt, or otherwise cause harm:

- Test destruction only on systems you own and are willing to lose/restore.
- Have a recovery plan before the test, not after.
- Bound the test to a non-production target.
- Capture the before and after state so the effect is known, not inferred.
- Never test destructive behavior against anything you do not control.

## Evidence Capture

Tests of security tools are themselves evidence of diligence:

- Capture the test environment, version of the tool, inputs, and expected behavior.
- Capture the outcome, including failures and unexpected behavior.
- Capture enough to reproduce the test later.
- For tools that generate evidence or findings, validate that the output matches what actually happened.

## Staging Before Live Use

Before any authorized live use:

- Exercise the tool in a controlled environment that resembles the live environment enough to be meaningful.
- Confirm the stop mechanism works.
- Confirm the logging/output is what you expect.
- Confirm the scope is what you think it is.
- Have a plan for what to do if the tool behaves unexpectedly in live use.

## Anti-Patterns

- **First run in production.** This is not a strategy; it is a gamble with other people's systems.
- **Testing only the happy path.** Security tools are judged on what they do under mismatch, failure, and misuse.
- **No recovery plan for destructive tests.** If you cannot recover the test target, you cannot safely test destruction.
- **Evidence not captured.** A test you cannot reconstruct is a test you cannot trust.
- **Blasting at everything.** Unbounded testing is not diligence; it is carelessness with a security tool.

## Decision Rule

Before a tool is used in any authorized live context:

1. Has it been exercised in a controlled environment you own or are authorized to use?
2. Have you tested what happens on failure and interruption, not only success?
3. Is the stop mechanism proven, not assumed?
4. Is the output/audit trail validated against a known result?
5. For any destructive capability, was it tested only on a target you control, with a recovery plan?

If any answer is "no," more lab work is needed.

## When to Load More

Load `06-data-evidence.md` to design the data and evidence story the tool will produce.
