# Security & Responsible Disclosure Policy

Triage is a tool for finding memory-safety bugs in real software. Finding a bug carries an
obligation to disclose it responsibly. This policy is non-negotiable and is part of what the
project is *for*: "I found it and I disclosed it properly" is what separates a security
engineer from someone running tools.

## For bugs found *with* Triage in third-party software

1. **Report privately, never in a public issue.** Find the channel first: the project's
   `SECURITY.md`, a `security.txt`, or its stated disclosure policy. On GitHub, use Private
   Vulnerability Reporting, which opens a draft GitHub Security Advisory (GHSA).
2. **Write a complete report:** affected versions, reproduction steps, the affected source
   lines, an estimated CVSS v3.1/v4.0 score and CWE, whether it is exploited in the wild, and
   a suggested fix.
3. **Set a 90-day disclosure deadline up front** (sooner if a fix ships first).
4. **Request a CVE** from the CNA whose scope covers the project (GitHub is itself a CNA and
   assigns one when a repo advisory is published; MITRE is the CNA of last resort). Feed OSV
   (osv.dev) when published.
5. **Coordinate the embargo.** For widely-used libraries, coordinate through the closed
   `linux-distros` list (≤14-day embargo) then public `oss-security`.

**Never published for unpatched, live code:** a working exploit. The public repo shows the
harness, the methodology, and findings only against already-patched releases or deliberately
pinned old versions. Anything live and unpatched stays private until fixed.

**Honesty guardrails.** Only a CVE that was actually assigned is called a CVE. "Reported and
fixed," "CVE assigned," and "0-day" are different claims and are never blurred. An automated
classifier's "likely exploitable" is a hint, not a demonstration.

The full mechanics, with current (2026) references, are in [`docs/DISCLOSURE.md`](docs/DISCLOSURE.md).

## For bugs *in Triage itself*

The demonstration target `targets/mferf/` is *intentionally* vulnerable — please do not report
its planted bugs. For a genuine bug in the harness, triage pipeline, or detection generator,
open a private report or contact the maintainer; there is no embargo requirement for this
repo's own code.
