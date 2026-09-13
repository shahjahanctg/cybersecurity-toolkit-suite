"""Custom Burp Suite Extension (generator) — W8 Extras.

Produces a Jython (Python) Burp Suite extension skeleton that hooks the
HTTP proxy request/response flow: an "Info" tab, per-request markers, and
a decorated request forwarder. Generates local .py only; running it inside
Burp is the user's own tester action on authorized targets.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="burp-extension",
    title="Custom Burp Suite Extension (Jython skeleton)",
    wave=8,
    description=(
        "Generate a starter Jython Burp extension that hooks the proxy "
        "through IBurpExtender / IHttpListener, exposes an Info tab, and "
        "tags requests. Local code generation only — drop it into Burp's "
        "Extender when you need it on your own engagements."
    ),
    category="extras",
    mode="read",
    privileges="none",
    destructive=False,
    fields=[
        FieldSpec(name="extension_name", label="Extension class name",
                  type="text", default="MarkerExtender"),
        FieldSpec(name="marker_header", label="Header to add (e.g. X-Checksum)",
                  type="text", default="X-Checksum"),
        FieldSpec(name="output_file", label="Output .py file", type="file",
                  default=None),
    ],
)


def _sanitize(name: str) -> str:
    import re
    name = re.sub(r"[^A-Za-z0-9_]", "", name)
    return name or "MarkerExtender"


def _render(ext_name: str, marker: str) -> str:
    return f'''"""
{ext_name} — generated Burp Suite extension skeleton (Jython).
Load via Extender -> Extensions -> Add -> Python. Hook runs on your
authorized targets only.
"""
from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, SwingConstants

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("{ext_name}")
        callbacks.registerHttpListener(self)
        self._panel = JPanel()
        self._panel.add(JLabel("{ext_name} active — requests are being "
                               "tagged with {marker}.",
                               SwingConstants.CENTER))
        self._count = 0

    def processHttpMessage(self, tool, messageIsRequest, message):
        if not messageIsRequest:
            return
        self._count += 1
        headers = self._helpers.analyzeRequest(message).getHeaders()
        headers.add("{{}}: hook-{{}}".format("{marker}".upper(), self._count))
        wrapped = self._helpers.buildHttpMessage(headers, message.getRequest()))
        message.setRequest(wrapped) if hasattr(message, "setRequest") else None

    def getTabCaption(self):
        return "{ext_name}"

    def getUiComponent(self):
        return self._panel
'''


def run(params: dict, ctx: ToolContext) -> dict:
    ext = _sanitize(str(params.get("extension_name") or "MarkerExtender"))
    marker = str(params.get("marker_header") or "").strip() or "X-Checksum"
    code = _render(ext, marker)
    written = ""
    out = params.get("output_file")
    if out:
        target = Path(str(out))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
        written = str(target)
    return {"extension_name": ext, "marker_header": marker,
            "python_code": code, "output_file": written}


def render(result: dict) -> str:
    lines = [f"Burp extension {result['extension_name']} (Jython skeleton)"]
    lines += result["python_code"].splitlines()
    if result.get("output_file"):
        lines.append(f"Written to {result['output_file']}")
    return "\n".join(lines)