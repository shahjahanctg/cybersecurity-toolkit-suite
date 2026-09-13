---
name: engineering-quality
description: "Safe coding, input handling, privilege minimization, sandboxing, error handling, auditability."
---

# 04 — Engineering Quality for Security Tools

## Core Mental Model

Security tools are ordinary software with unusually high stakes for safety, correctness, and auditability. The engineering bar is higher, not lower, because the tool operates in a security context. A tool that is clever but unsafe is worse than a tool that is boring and safe.

## Input Handling

- Validate all input at the boundary. Tool input includes command-line arguments, config files, stdin, network data, file input, and environment variables.
- Distinguish expected input from unexpected input. Reject or sanitize the latter; do not silently reinterpret it.
- Be careful with input that becomes control flow, file paths, commands, queries, or anything interpreted by another system.
- When the tool reads from a system or network, treat that data as untrusted until validated.

## Privilege Minimization

- Run with the minimum privilege the tool needs for its function.
- Default-deny privilege: if a capability is not required, the tool should not have it.
- Avoid "run as root/admin because it is easier." Ease of implementation is not a legitimate reason to expand the privilege surface.
- Where the tool needs elevated capability for part of its work, confine that part and drop privileges where possible.
- Document why any elevated privilege is required.

## Safety by Design

- **Destructive potential** — if the tool can change, remove, or disrupt state, make that path explicit, gated, and auditable. The default should not be destructive.
- **Accidental misuse** — design so that a mistaken invocation does less harm. Confirmations, dry-run modes, scoping checks, and guarded defaults all help.
- **Fail safe** — when the tool fails, it should fail in a way that does not make the situation worse (no partial state that looks like success, no maskable errors).
- **Bounded impact** — where possible, bound the tool's blast radius (a single target, a single file, a single scope) rather than allowing unbounded operation.

## Sandboxing & Confinement

- Where the tool interacts with untrusted input or performs risky operations, consider confinement (container, sandbox, restricted user, reduced capability set) appropriate to the risk.
- Confinement is a mitigation, not a substitute for safe code. A sandboxed unsafe tool is still an unsafe tool.
- For tools that must interact with the host or other systems, confinement is a tradeoff — document the decision.

## Error Handling

- Errors should be handled explicitly, not swallowed.
- Distinguish expected errors (target not found, permission denied within scope, input invalid) from unexpected errors (bugs, invariants violated).
- Errors should carry enough context to understand what happened without exposing more than necessary.
- The operator sees a useful message; the log sees the diagnostic detail.
- Do not leak sensitive data in error output.

## Auditability in Code

- The tool should be able to report what it did in a structured, attributable way.
- Log the operation, the scope, the result, and any stop conditions.
- Where the tool's behavior has security significance, the log should be sufficient to reconstruct the operation later.
- Avoid logging more than the operation needs — logging is itself a data-handling decision.
- Make the audit trail tamper-evident where the tool's use warrants it (e.g. signed logs, append-only storage, integrity checks).

## Code Quality & Maintainability

- Names describe intent. A function called `doit` is a liability; a function called `collectHostInfo` tells the reader something.
- One reason to change per module. If a module needs "and" to describe its job, split it.
- Keep dangerous code small, visible, and reviewable. Do not bury risky behavior inside a large helper.
- Avoid silent dependency on environment assumptions. Be explicit about what the tool requires.

## Dependencies

- Know what your dependencies do. A security tool with a hidden or unaudited dependency is a hidden surface.
- Prefer well-maintained, appropriate dependencies over one-off copies of code you do not fully understand.
- For tools that process sensitive data or perform security-critical operations, dependency review is part of the engineering, not an afterthought.

## Anti-Patterns

- **Root by default.** Privilege is a design decision, not a convenience.
- **Silent failure.** A tool that fails quietly is a tool whose failure you will not notice.
- **Unbounded operation.** A tool that can act on everything without a stop is a tool waiting for a mistake.
- **Input trust.** Treating input as trusted because it "comes from the operator" is a common and expensive mistake.
- **Hidden dangerous behavior.** Risky operations buried in unreadable code are risky operations no one reviews.

## Decision Rule

For every significant piece of behavior in the tool, ask:

1. What is the worst credible thing this code can do if it goes wrong?
2. Is that worst case bounded, stoppable, and auditable?
3. Does the code run with only the privilege it needs?
4. Is the path clear enough that someone other than the author could review it?

If the answer to any of these is weak, that is where to invest engineering effort.

## When to Load More

Load `05-testing-validation.md` to see how to exercise the tool safely before any authorized use.
