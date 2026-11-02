# Security Policy

## Supported versions

Security fixes are released for the latest published version only. Older
versions are not patched; the fix ships in a new release.

| Version | Supported |
|---------|-----------|
| 1.4.0   | ✅ |
| < 1.4.0 | ❌ |

Since 1.0.0 the public API is frozen, so a security fix ships in a
backwards-compatible patch or minor release. The ChangeLog marks breaking
changes explicitly.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting][advisories] on
https://github.com/bermannoah/dmarcator. Please do not open a public issue.

Include, as far as you can:

- the version affected, and the Ruby and `resolv` versions,
- the input that triggers the problem (a DMARC record, report, or domain name),
- what you expected and what happened,
- whether the DNS transport was plaintext, DNS over HTTPS, or DNS over TLS.

You will get an acknowledgement, an assessment, and a coordinated disclosure
date. Credit is given in the ChangeLog unless you ask otherwise.

## What this library treats as untrusted

Everything it parses or resolves is untrusted, and the design assumes so:

- **DMARC records** come from DNS and are parsed by a grammar with input
  bounds; error messages echoing input are truncated.
- **DMARC XML reports** are untrusted documents. DTDs and entity declarations
  are rejected outright, network access and entity expansion are disabled, the
  report must have a `<feedback>` root element, and structural complexity
  (nodes, depth, records, text, attributes and per-record `auth_results`/
  `reason` entries) is bounded by configurable limits before a DOM is built.
- **Domain names** are validated before reaching the resolver.
- **DNS responses** are validated by the encrypted transports (transaction id,
  question, truncation bit), and TLS certificates are always verified.

These library limits bound the work the C parser is asked to do, but they are
not the outer boundary: a `nokogiri`/libxml2 bug could still bypass Ruby-level
checks. Applications parsing reports from untrusted sources should run the
parse in an isolated worker or subprocess with its own resource limits.

Lookup failures fail closed: a transport error raises
`DMARCator::ResolutionError` rather than being reported as "no DMARC record",
so a blocked or degraded resolver cannot silently result in no policy being
enforced.

## In scope

- Parser bugs reachable from a DMARC record, an XML report, or a domain name:
  crashes, unbounded memory or CPU, entity expansion, unsafe reflection.
- Transport bugs: TLS verification bypass, response spoofing not caught by the
  id/question checks, request smuggling, unbounded response buffering.
- Silent fail-open behaviour: any path where a failure is reported as an
  absent record.

## Out of scope

- Vulnerabilities in `nokogiri`, `resolv`, or Ruby itself. Report those
  upstream; the library's load-time guard for known `resolv` issues is a
  warning, not a substitute for patching.
- The *policy* decisions of an application built on the library, such as
  whether to fail open on `DMARCator::ResolutionError`.
- Misconfiguration of the caller's resolver, or the trustworthiness of a
  third-party DNS provider chosen by the caller.

## Hardening already applied

The ChangeLog records these, and the README documents the current behaviour:
DTD and entity declarations rejected outright (XXE and entity expansion are
impossible), a required `<feedback>` root element, network and DTD loading
disabled, report and record size caps, structural limits on nodes, depth, text
length, attributes and per-record entries (all enforced before a DOM is
built), `pct`/`ri` range checks, duplicate-tag rejection, strict
`mailto:`-only report URIs, DNS name validation, TLS verification, and the
`resolv` CVE guard.

[advisories]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
