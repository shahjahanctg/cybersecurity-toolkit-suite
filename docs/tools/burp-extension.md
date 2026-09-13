# burp-extension — Custom Burp Suite Extension (W8)

Generates a Jython (Python) Burp Suite extension skeleton that hooks the
proxy through `IBurpExtender`/`IHttpListener`, exposes an Info tab, and tags
each proxied request with the marker header you name. Output is a single
local `.py` you load into Burp's **Extender → Add → Python**.

## What it does NOT do
- Does not run Burp, does not proxy anything, makes no network traffic.
- The generated hook only ever runs inside *your* Burp installation, on
  targets you configure.

## Authorized use
Adding request taggers / analyzers to Burp for engagements you own. Dropping
a hooked proxy onto targets without written authorization is prohibited.

## Prerequisites
None to generate. Using it requires Burp Suite (Community works) with the
Jython standalone jar loaded as its Python environment.

## Usage
```bash
sec-toolkit burp-extension --extension-name MarkerExtender \
    --marker-header X-Checksum --output-file ./marker.py
```

## Output
`{extension_name, marker_header, python_code, output_file?}`.

## Safety notes
- Mode is read/codegen; the output file is the only thing written.
- The skeleton appends a plain ASCII marker header; it never logs bodies or
  secrets.

## Limitations
- Jython compatibility is assumed (Python 2-era stdlib only, no f-strings).
- `message.setRequest` fallback is toy-grade; production extensions should
  use `callbacks` helpers to rebuild the request.

## Version
0.1.0