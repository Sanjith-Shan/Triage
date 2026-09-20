# Methodology

Triage has five parts. Parts 2–5 are what make it more than "I ran AFL."

## 1. Fuzz drivers and the build matrix

One `LLVMFuzzerTestOneInput` driver per target, built under ASan, UBSan and (on Linux) MSan,
plus an AFL++ persistent build. Seed corpora from real inputs; per-format dictionaries of magic
bytes and keywords (`dict/`). **Reached-edge coverage is reported per target** so a reader
knows the fuzzer entered the parser rather than bouncing off the front door — the metric the
OpenSSL punycode story (below) turns on.

## 2. Structure-aware mutation — the core

Random byte-flipping barely enters a length-prefixed or grammar-based format; it fails the
first magic/type/length check and never reaches the code where bugs live. Triage drives a
**structure model per format** through `LLVMFuzzerCustomMutator` (grammar-aware), keeping the
framing valid while corrupting one field at a time — including pushing length fields to the
integer boundaries where overflow bugs live.

This is measured, not asserted. The **head-to-head** compares the structure-aware mutator
against naive byte mutation on the same target, seeds, and budget:
- `LLVMFuzzerReached` counts how often each mutant reaches deep code;
- crash yield at equal budget is the blunter, stronger signal.

See [`../NUMBERS.md`](../NUMBERS.md) for measured results. Same move as Basalt (vectorized vs
row-at-a-time) and NanoExchange (four hash tables): the numbers pick the winner, not the author.

## 3. Differential fuzzing, and the angles it carries

Where a format has two independent parsers, fuzz both on identical input and diff the decoded
result. A divergence is a bug in one or an interop hazard in the spec — either is real. Three
differentials each carry a security area honestly:

- **HTTP parser differential → request smuggling / desync** (`targets/http_diff/`). Two
  independent HTTP/1.1 framing parsers disagree on where a request ends (CL.TE / TE.CL / TE.TE);
  the divergence is the smuggling *primitive*. Prior art: T-Reqs (CCS 2021), HTTP Garden
  (arXiv 2405.17737). **Ceiling:** this is server/proxy-side HTTP desync — a web-*infrastructure*
  and *protocol* problem — not browser security or XSS/SQLi, and proving end-to-end impact
  needs a real front-end/back-end proxy lab.
- **ASN.1 / X.509 / DER** → applied-cryptography / security-protocols. Structure-aware DER
  fuzzing plus a differential that flags accept/reject disagreements between parsers (the
  cross-implementation trust-confusion class; cf. frankencert). The senior talking point is why
  OSS-Fuzz *missed* CVE-2022-3602/3786 — an X.509 harness with zero coverage of the vulnerable
  path — which is exactly the argument for part 1's coverage metric. **Ceiling:** parsing the
  *messages* of crypto protocols, not implementing or breaking crypto.
- **JWT / JOSE** → authentication control. Two prongs, and the distinction is the signal:
  (1) a memory fuzzer over a C JOSE library finds parse/memory bugs; (2) a *separate* logic
  oracle checks algorithm-confusion / `alg:none` — which a coverage-guided memory fuzzer will
  **not** find, because those tokens verify without crashing. **Ceiling:** input-hardening of
  an auth-token library, not "I tested authentication."

## 4. Triage and exploitability classification — the honesty thesis

- **Dedup** by ASLR-normalized ASan stack-hash (major = top 3 frames, minor = top 7), sanitizer
  frames stripped. Tens of thousands of crashes collapse to the handful of distinct bugs.
- **Minimize** each unique crash with ddmin, preserving the *specific* bug (the reproducer
  re-runs the target and checks the crash bucket still matches).
- **Classify**, least → most severe: DoS / uncontrolled-recursion → OOB-read → OOB-write →
  use-after-free. Then the axes that matter more than the label: controlled-offset vs
  controlled-value, reachable-from-untrusted-input, mitigations in play. Pulled from the
  sanitizer report, not guessed — unknowns stay `None`.
- **Root-cause** each unique bug in prose.

Exploitability is capped by evidence: the pipeline emits only `crash` or `likely-exploitable`;
`PoC-to-primitive` and `weaponized` require a manual demonstration. **A crash is not an
exploit**, and `!exploitable`-style output is a heuristic hint, not proof. Writing "probable
OOB-write, attacker-controlled offset, no working exploit developed" is more credible than an
"RCE" that turns out to be a NULL-deref DoS.

## 5. Detection-signature generation — the fuzzing → intrusion-detection bridge

For each confirmed bug, `detect/` emits a detection rule (YARA for host/file, Suricata for
network). The design principle: a rule matching the literal PoC bytes is a worthless
atomic-of-one overfit; a credible rule matches the **vulnerability-triggering invariant** — the
coexisting Content-Length + Transfer-Encoding headers for the smuggling bug, the oversized
length field for an overflow, the nesting depth for a recursion bug. Every rule ships with a
true-positive rate on held-out mutated triggers and a false-positive rate on a benign corpus.
It is positioned as virtual patching / detecting known-bug-class attempts — **not** a novel
IDS, and it does not generalize to unknown attacks.

## The one deep dive

Take the single best finding all the way: crash → root cause → a demonstrated primitive → the
fix → a regression test that fails on the unpatched code → the detection signature → the
disclosure. "It segfaults" → "here is the primitive, the patch, the detecting rule, and the
CVE" is the intern-tier win, and it is real.

## Keeping it honest

1. A novel bug on a schedule is not guaranteed, so the resume claim is the harness and method,
   which exist regardless. A **seeded rediscovery** against a pinned known-CVE version (FreeType
   CVE-2025-27363) guarantees a complete narrative independent of luck.
2. Every number is measured and lives in [`../NUMBERS.md`](../NUMBERS.md) with its machine and
   target version. Losing to the incumbent, or a mutator tweak that didn't help, gets published.
