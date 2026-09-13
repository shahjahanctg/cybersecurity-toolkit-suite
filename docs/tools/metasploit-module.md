# metasploit-module — Custom Metasploit Module Generator (W7)

Generates a starter Metasploit Ruby module (auxiliary / exploit / post)
targeting the service you specify, with the standard `initialize`/`check`/
`run`-or-`exploit` structure and reference stubs. It writes `.rb` code locally
and exits.

## What it does NOT do
- Does not run Metasploit, `msfvenom`, or anything on the network.
- Modules are skeletons for you to fill in for your authorized targets.

## Authorized use
Learning Metasploit module structure. Running generated modules against a
host you do not own requires written authorization.

## Prerequisites
None to generate. To *use* the output you need a Metasploit installation and
a test target you are authorized to evaluate.

## Usage
```bash
sec-toolkit metasploit-module --module-name lab_bof --module-type exploit \
    --default-port 4444 --output-file ./lab_bof.rb
```

## Output
`{module_name, module_type, default_port, ruby_code, output_file?}`.

## Safety notes
- The generator itself performs no network activity — it only writes `.rb`.
  Run the generated modules only against systems you are authorized to test.

## Limitations
- Generated code is illustrative; adjustments to ranks, targets, and payload
  options are expected before real use.

## Version
0.1.0