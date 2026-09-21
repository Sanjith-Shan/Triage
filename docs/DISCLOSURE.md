# Coordinated disclosure — the mechanics

This is the workflow Triage follows for any bug found in live third-party code. It is written
out because the process *is* the SDLC signal the project buys: operating inside it proves you
can be trusted with sensitive information, communicate with maintainers, respect an embargo,
and understand where security sits in the software lifecycle. The authoritative reference is
the OpenSSF OSS Vulnerability Guide (finder guide).

## Steps

1. **Find the reporting channel.** In order of preference: the repo's `SECURITY.md`; a
   `security.txt` on the project's site; the project's published disclosure policy; a foundation
   or the CVE Program partner list; last resort, the maintainers privately. Never a public
   issue or PR — that is a 0-day drop.

2. **Report privately.** On GitHub, the repo's Security tab → *Report a vulnerability* (Private
   Vulnerability Reporting) creates a draft **GitHub Security Advisory (GHSA)** visible only to
   you and the maintainers. For non-GitHub projects, use the channel from step 1.

3. **Write the report for public consumption**, so it can become the advisory verbatim:
   - affected versions / commit range;
   - a minimal reproduction (the minimized crashing input from `triage --minimize`);
   - the faulting source lines and the bug class (from the ASan/UBSan report);
   - an estimated **CVSS v3.1 or v4.0** vector and score, and the **CWE**;
   - whether it is known-exploited;
   - a suggested patch and a regression test.

4. **State the timeline up front.** The current norm is a **90-day** disclosure deadline
   (Google Project Zero; CERT/CC uses 45–90), or sooner if a fix ships earlier. Say so in the
   first message.

5. **Get a CVE.** Request it from the **CNA** whose scope covers the project. In practice for
   OSS in 2026 this is usually **GitHub** (itself a CNA), which assigns a CVE when the repo
   advisory is published; where no CNA covers the project, **MITRE is the CNA of last resort**.

6. **Coordinate the embargo and release.** The fix is developed and tested privately; the
   advisory, patch, and CVE are disclosed together. For a library many vendors ship, coordinate
   pre-disclosure through the closed **`linux-distros`** list (embargo ≤ 14 days), then announce
   publicly on **`oss-security`**. Publish the GHSA/CVE and, ideally, an **OSV** record
   (osv.dev) so scanners pick it up.

## The disclosure spectrum

Coordinated (preferred) → Limited → Full → 0-day (discouraged). Triage always aims for
coordinated.

## References

- OpenSSF OSS Vulnerability Guide (finder guide): https://github.com/ossf/oss-vulnerability-guide/blob/main/finder-guide.md
- GitHub Private Vulnerability Reporting: https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability
- GitHub as a CNA: https://github.blog/security/vulnerability-research/how-to-request-a-change-to-a-cve-record/
- OWASP Vulnerability Disclosure Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html
- OSV: https://osv.dev
