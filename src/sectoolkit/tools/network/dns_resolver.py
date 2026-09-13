"""DNS Resolver + Cache-Poisoning Lab — W1 Network Recon.

Two modes:
  * resolve   — standard A/AAAA/MX/NS/TXT/CNAME resolution (dnspython).
  * poison-lab — local educational simulation of DNS cache poisoning.
                 A local in-process "caching resolver" demonstrates why
                 transaction-ID + source-port randomization defeats spoofing.
                 Everything runs on loopback / in memory; no packets leave
                 your machine and no real resolver is touched.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List

from ...core.tool import FieldSpec, ToolContext, ToolMeta

TOOL = ToolMeta(
    name="dns-resolver",
    title="DNS Resolver + Cache-Poisoning Lab",
    wave=1,
    description=(
        "Resolve DNS records for a domain, or run a local educational simulation "
        "that demonstrates DNS cache-poisoning defenses. The lab runs entirely "
        "locally and never sends packets beyond your machine."
    ),
    category="network",
    mode="act",
    privileges="none",
    # The poison lab runs entirely in local memory and the resolver queries
    # are ordinary lookups, so no field is a scanned target for the guard.
    target_fields=[],
    fields=[
        FieldSpec(name="mode", label="Mode", type="combo", default="resolve",
                  options=["resolve", "poison-lab"],
                  help="resolve: real DNS lookups; poison-lab: local lab simulation"),
        FieldSpec(name="domain", label="Domain", type="text", required=True,
                  placeholder="example.org",
                  help="Domain to resolve (resolve mode) or victim domain (lab)"),
        FieldSpec(name="types", label="Record types", type="text", default="A,AAAA,MX,NS,TXT",
                  help="Comma-separated record types for resolve mode"),
        FieldSpec(name="server", label="DNS server", type="text", default="",
                  placeholder="(system resolver)",
                  help="Optional DNS server to query (empty = system resolver)"),
        FieldSpec(name="resolver_mode", label="Resolver mode", type="combo",
                  default="strong", options=["weak", "strong"],
                  help="lab: weak = fixed txid + fixed source port; "
                       "strong = randomized (defended)"),
        FieldSpec(name="iterations", label="Lab iterations", type="int", default=200,
                  help="lab: spoofing guesses to simulate"),
        FieldSpec(name="timeout", label="Timeout (s)", type="int", default=5,
                  help="Per-query timeout in seconds (resolve mode)"),
    ],
)

_DNS_TYPES_ORDER = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]
_TYPES_INDEX = {t: i + 1 for i, t in enumerate(_DNS_TYPES_ORDER)}


# ---------------------------------------------------------------------------
# Resolve mode
# ---------------------------------------------------------------------------

def run(params: dict, ctx: ToolContext) -> dict:
    mode = params.get("mode", "resolve")
    domain = str(params.get("domain", "")).strip().rstrip(".")
    if not domain:
        raise ValueError("a domain is required")
    if mode == "poison-lab":
        return _run_poison_lab(params)
    return _run_resolve(domain, params, ctx)


def _run_resolve(domain: str, params: dict, ctx: ToolContext) -> dict:

    import dns.resolver


    server = str(params.get("server") or "").strip()
    timeout = int(params.get("timeout") or 5)
    type_tokens = [t.upper().strip() for t in str(params.get("types") or "A").split(",")]
    type_tokens = [t for t in type_tokens if t]

    resolver = dns.resolver.Resolver(configure=not server)
    if server:
        resolver.nameservers = [server]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records: List[dict] = []
    errors: List[dict] = []
    for t in type_tokens:
        try:
            answers = resolver.resolve(domain, t)
            ttl = getattr(answers.rrset, "ttl", None)
            for answer in answers:
                records.append({
                    "type": t,
                    "ttl": ttl,
                    "data": str(answer),
                })
        except dns.resolver.NoAnswer:
            errors.append({"type": t, "error": "no answer"})
        except dns.resolver.NXDOMAIN:
            errors.append({"type": t, "error": "NXDOMAIN (name does not exist)"})
        except dns.resolver.LifetimeTimeout:
            errors.append({"type": t, "error": "timeout"})
        except dns.resolver.NoNameservers:
            errors.append({"type": t, "error": "no nameservers"})
        except Exception as exc:
            errors.append({"type": t, "error": f"{type(exc).__name__}: {exc}"})

    return {
        "mode": "resolve",
        "domain": domain,
        "server": server or "system resolver",
        "records": records,
        "record_count": len(records),
        "errors": errors,
    }


def render(result: dict) -> str:
    if result.get("mode") != "resolve":
        return _render_lab(result)
    lines = [f"DNS lookup for {result['domain']} via {result['server']}"]
    if result["records"]:
        lines += ["", f"{'TYPE':<8}{'TTL':<6}{'DATA'}", "-" * 70]
    for r in result["records"]:
        lines.append(f"{r['type']:<8}{r.get('ttl') or '-':<6}{r['data']}")
    for e in result["errors"]:
        lines.append(f"  [{e['type']}] {e['error']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Poison-lab mode (local in-memory simulation)
# ---------------------------------------------------------------------------

@dataclass
class _CachingResolver:
    """Minimal model of a recursive resolver's cache with optional defense."""

    mode: str  # "weak" or "strong"
    cache: Dict[str, str] = field(default_factory=dict)
    _authoritative_a: str = "198.51.100.10"
    _attacker_a: str = "203.0.113.66"

    def choose_txid(self) -> int:
        if self.mode == "weak":
            return 0x1234
        return random.randrange(0, 1 << 16)

    def choose_srcport(self) -> int:
        if self.mode == "weak":
            return 53535
        return random.randrange(1024, 65535)

    def legitimate_resolve(self, name: str) -> str:
        """Resolver's honest lookup: answers from the authoritative source."""
        self.cache[name] = self._authoritative_a
        return self._authoritative_a

    def offer_response(self, name: str, observed_txid: int, observed_port: int,
                       guessed_txid: int, guessed_port: int) -> bool:
        """True when the spoofed response passes the cache-injection checks."""
        if guessed_txid != observed_txid:
            return False
        if guessed_port != observed_port:
            return False
        return True

    def attempt_spoof(self, name: str, known_txid: int | None,
                      known_port: int | None) -> bool:
        """One spoofing attempt against a freshly generated query."""
        txid = self.choose_txid()
        port = self.choose_srcport()
        if self.mode == "weak":
            guess_txid, guess_port = known_txid or txid, known_port or port
        else:
            guess_txid, guess_port = random.randrange(0, 1 << 16), random.randrange(1024, 65535)
        if self.offer_response(name, txid, port, guess_txid, guess_port):
            self.cache[name] = self._attacker_a
            return True
        return False


def _run_poison_lab(params: dict) -> dict:
    victim = str(params.get("domain", "")).strip().rstrip(".")
    mode = params.get("resolver_mode", "strong")
    iterations = int(params.get("iterations") or 200)
    if iterations > 10000:
        raise ValueError("lab iterations capped at 10000")

    resolver = _CachingResolver(mode=mode)
    resolver.legitimate_resolve(victim)
    accepted = 0
    for _ in range(iterations):
        resolver.cache.pop(victim, None)
        if resolver.attempt_spoof(victim, None, None):
            accepted += 1

    pct = 100.0 * accepted / max(1, iterations)
    if mode == "weak":
        expected = ("A spoofed answer is accepted nearly every time because the "
                    "attacker knows the (fixed) transaction ID and source port.")
        outcome = "poisoned"
    else:
        expected = ("A spoofed answer virtually never passes, because the "
                    "attacker must guess the 16-bit transaction ID AND the "
                    "randomized source port (2 x 16 bits of entropy).")
        outcome = "defended"
    final_cache = resolver.cache
    return {
        "mode": "poison-lab",
        "victim_domain": victim,
        "resolver_mode": mode,
        "iterations": iterations,
        "accepted": accepted,
        "rejected": iterations - accepted,
        "acceptance_percent": round(pct, 3),
        "outcome": outcome,
        "final_cache": sorted(final_cache.items()),
        "explanation": expected,
        "caution": (
            "Simulation only. No packets left your machine. Real cache "
            "poisoning against a live resolver is an attack — never do it "
            "without written authorization. DNSSEC is the additional, modern "
            "defense layer this lab does not model."
        ),
    }


def _render_lab(result: dict) -> str:
    defense = {
        "weak": "FIXED txid + source port",
        "strong": "randomized txid + source port",
    }[result["resolver_mode"]]
    return (
        f"Cache-poisoning lab simulation for {result['victim_domain']}\n"
        f"  resolver defense mode : {result['resolver_mode']} ({defense})\n"
        f"  spoofing attempts     : {result['iterations']}\n"
        f"  accepted              : {result['accepted']}\n"
        f"  rejected              : {result['rejected']}\n"
        f"  acceptance rate       : {result['acceptance_percent']}%\n"
        f"  outcome               : {result['outcome']}\n"
        f"\n{result['explanation']}\n"
        f"\n{result['caution']}"
    )