# Architecture — Security Toolkit Suite

## Guiding principles (from the build prompt + cyber-toolkit-dev skill)

1. **Authorized use is a feature, not a warning.** Every tool documents its
   legal/ethical boundaries (see `docs/permissions.md`), and network-touching
   or destructive tools print an authorized-use banner before every run.
2. **Structured output everywhere.** Every tool emits JSON (CLI `--json`) plus a
   human-readable render; results are enveloped with tool/version/time/params.
3. **Safety rails in code, not memos.** Raw-socket tools fail fast with
   actionable guidance; network/proxy/vulnscan/red-team and destructive tools
   show an authorized-use banner; deceptive/destructive tools require
   confirmation.
4. **Minimal privilege.** Tools declare `privileges: none | net_raw | root | admin`
   and only the code paths that need them elevate/check. No tool runs as root
   "because it's easier".

## Monorepo layout

```
src/sectoolkit/
├── cli/            # entry points + argparse runner (registry -> subcommands)
│   ├── main.py
│   └── runner.py
├── core/           # shared libraries (framework, no tool logic)
│   ├── config.py        # JSON config, per-tool defaults
│   ├── logging_setup.py # structured logging + redaction hook
│   ├── netutil.py       # CIDR math, VLSM, port/host parsing
│   ├── output.py        # JSON + table rendering
│   ├── privileges.py    # capability detection (Linux caps / admin)
│   ├── registry.py      # single source of truth for all tools
│   └── tool.py          # ToolMeta, FieldSpec, ToolContext, safety_check
├── gui/            # PySide6 desktop app (dark theme by default)
│   ├── app.py          # console entry `sec-toolkit-gui`
│   ├── dashboard.py    # wave dashboard + settings + log dock
│   ├── logviewer.py    # stdlib logging -> Qt panel
│   ├── theme.py        # dark QSS + Fusion palette
│   └── toolpage.py     # generic form/run/output generated from ToolMeta
└── tools/          # one module per tool, grouped by wave
    ├── network/        # W1
    ├── defense/        # W2
    ├── proxy/          # W3
    ├── vulnscan/       # W4
    ├── forensics/      # W5
    ├── malware/        # W6
    ├── redteam/        # W7
    └── extras/         # W8
```

## One contract for CLI + GUI: `ToolMeta` + `run(params, ctx)`

Every tool module defines:

```python
TOOL = ToolMeta(name=..., title=..., wave=1, category="network",
                privileges="none", destructive=False,
                fields=[FieldSpec(name="host", label="Target", type="text",
                                  required=True, help="...")])

def run(params: dict, ctx: ToolContext) -> dict: ...
def render(result: dict) -> str: ...          # optional human view
```

- The **CLI** (`sec-toolkit <name> …`) generates argparse flags from `fields`.
- The **GUI** generates a form + run button + output panel from the same `fields`.
- `ToolContext` carries config, logger, output dir, cancellation state.
- `safety_check()` in `core/tool.py` surfaces capability warnings (raw-socket
  tools) before any tool runs; `requires_authorization()` decides which tools
  print the authorized-use banner.

## Cross-cutting concerns

| Concern | Decision |
|---|---|
| Output | `--json` envelopes; each tool also has a human `render()` |
| Config | JSON global config (`~/.config/sec-toolkit/config.json`), per-tool defaults in `config.tool_defaults` |
| Logging | structured `sectoolkit.*` logger to stderr + file; `RedactingFormatter` scrubs secrets |
| Permissions | declaration + capability check; see `docs/permissions.md` |
| Cancellation | `ctx.extra["stop_event"]` set by CLI SIGINT or GUI Cancel; tools poll cooperatively |
| Safety rails | authorized-use banner for network/vulnscan/proxy/red-team + destructive tools; raw-socket capability warnings; one-target-by-default bounds |

## Threading model (GUI)

Each `ToolPage` runs its tool in a dedicated `QThread`. A `Cancellation()` event
lives in `ctx.extra["stop_event"]`; blocking sockets use timeouts so the run
always terminates. `closeEvent` requests cancellation and joins threads within
3 s.

## Packaging

- Source install via `pip install -e .` (console scripts `sec-toolkit`,
  `sec-toolkit-gui`).
- Optional `[gui]` extra for PySide6, `[dev]` for pytest + pip-audit.
- `Dockerfile` provides an isolated lab image (see README).

## Testing philosophy

- Unit tests cover parsing, math (VLSM, CIDR), and formatting — no privileges.
- Integration tests use loopback-only servers (localhost TCP banner, temp PCAP).
- Privilege-gated live scans are marked `@pytest.mark.priv` and skipped CI-less;
  their logic is exercised through mocks.
- GUI smoke tests run headless via `QT_QPA_PLATFORM=offscreen`.