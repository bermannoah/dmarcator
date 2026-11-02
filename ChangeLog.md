### 1.4.1 / 2026-11-02

* Update `nokogiri` dependency to `>= 1.19.5`, patches CVEs in nokogiri upstream.

### 1.4.0 / 2026-11-01

* Enforce the per-record `max_auth_results` and `max_reasons` limits eagerly during the streaming pre-check, before any DOM is built. Previously a report with one record containing an enormous `auth_results`/`reason` collection reached DOM construction unless another global limit caught it.
* Require a `<feedback>` root element: well-formed XML that is not a DMARC aggregate report is rejected with `InvalidReport` instead of being parsed into an empty report.
* Stop echoing libxml2 error text (which can contain tag, attribute or entity names from the untrusted input) in `InvalidReport` messages; report only line and column position.
* Add near-limit regression tests (reports just below every configured limit still parse) and a deterministic fuzz test that random bytes, tag soup, huge text and many attributes only ever raise `DMARCator::Error`.

### 1.3.0 / 2026-11-01

* Treat report XML as hostile by rejecting DTD and entity declarations outright (`DMARCator::ForbiddenXml`). DMARC reports never need a DTD, so external-entity (XXE) and entity-expansion (billion-laughs) attacks are rejected before parsing rather than merely having their resolution disabled.
* Parse report XML with an explicit hardening policy: `NONET` on, entity substitution, DTD loading, default DTD attributes and libxml2's `HUGE` relaxation all off, and strict (non-recovering) parsing.
* Bound report structural complexity with configurable limits enforced by a streaming reader before any DOM is built. Exceeding a limit raises `DMARCator::ReportTooComplex` rather than `InvalidReport`.
* Add `Config` limits `max_report_records` (10,000), `max_xml_nodes` (100,000), `max_xml_depth` (50), `max_text_length` (1 MiB), `max_xml_attributes` (100,000), `max_auth_results` (100) and `max_reasons` (100).
* Add `DMARCator::ReportTooComplex` and `DMARCator::ForbiddenXml` error classes (both `DMARCator::Error`).

### 1.2.1 / 2026-10-30

* Add a record-parser corpus regression net: 143 records (published real-world records plus edge cases) with their accepted outcomes in lenient and strict mode, replayed by the test suite. A parser change that alters how any record parses now fails with a diff. Regenerate with `script/generate_record_corpus.rb`.
* Report a TCP response body shorter than its declared length as `short DNS response (expected N bytes, got M)`, instead of the opaque `malformed DNS response: limit exceeded`.

No public API changes.

### 1.2.0 / 2026-10-30

* Plaintext lookups now use DNS over TCP (`DMARCator::Resolver::Plain`) instead of `Resolv::DNS`. `Resolv` reads UDP replies into a 512-byte buffer, so a larger answer cannot be decoded, is discarded, and the resulting timeout is swallowed. Any TXT set over 512 bytes — common for SPF and for domains with several DKIM keys — was therefore returned as an empty array, which is indistinguishable from "no records published". TCP has no such limit, and failures raise `ResolutionError`.
* `DMARCATOR_DNS_TIMEOUT` now applies to plaintext lookups as well (default 5 seconds).
* `DMARCator::DNS_TIMEOUTS` is no longer used and is deprecated; it will be removed in 2.0.
* An injected `Resolv::DNS` still works, but carries the same 512-byte UDP limitation. Use `DMARCator::Resolver::Plain`, DoH, or DoT for SPF and DKIM accuracy.

### 1.1.0 / 2026-10-30

* Replace the Parslet grammar with a hand-written parser in `DMARCator::Internal`. Parsing behaviour is unchanged, verified differentially against the previous parser over 128 real-world and 47 edge-case records in both lenient and strict modes; record parsing is roughly 30x faster (0.84 ms to 0.03 ms per record).
* Remove the `parslet` runtime dependency. `nokogiri` is now the only runtime dependency.
* Messages for structurally malformed records now come from the parser itself (for example `invalid DMARC record: "..."`) and are truncated to 300 characters.
* `DMARCator::Internal::Parser::Transform` no longer exists. It was internal, so this is not covered by the compatibility promise.
* Reject records whose string encoding is invalid or not ASCII-compatible with `InvalidRecord`. Previously `Record.parse` could raise `ArgumentError` (invalid UTF-8) or `Encoding::CompatibilityError` (for example UTF-16), which escaped `rescue DMARCator::Error`. Binary strings from a DNS resolver, and other ASCII-compatible encodings such as ISO-8859-1, are unaffected.

### 1.0.0 / 2026-10-30

The public API is now frozen.

* The contract spec added in 0.12.0 defines the supported surface: the module methods, constants and per-class public methods it asserts. Anything documented as `@api private` may still change in a minor release.
* Deprecations are documentation-only, and removals happen only in a major release. `Report.max_report_bytes`, `Report.max_report_bytes=` and `Report::MAX_REPORT_BYTES` are deprecated in favour of `DMARCator.configure` and `Config::DEFAULT_MAX_REPORT_BYTES`, and will be removed in 2.0.
* Supported Ruby is `>= 3.3.13`. Dropping a Ruby series is the one documented exception to the no-breaking-changes promise: it is announced in a minor release and removed in the next major.
* Parsed report values are now frozen, not merely reader-only: the strings taken from the document and the arrays holding records, errors, reasons, auth results and the parsed record's `rua`/`ruf`/`fo` cannot be mutated in place. `Record` and the report value objects are therefore safe to share between threads.
* The parser and XML helper moved to `DMARCator::Internal`, so the public constants are only documented API and the parser can be replaced in a minor release.
* Parsing, lookup and transport behaviour are unchanged from 0.12.0; the differences above are the freeze itself.

### 0.12.0 / 2026-10-29

Breaking changes, taken before 1.0:

* `Report#version` returns the published value as a String instead of a `BigDecimal`, and the `bigdecimal` runtime dependency is gone. A non-numeric version still yields `nil`.
* Parsed report objects (`Report::Metadata`, `Policy`, `Row`, `AuthResult`, `Reason`) are read-only. Their attributes were previously writable, which allowed a parsed report to be mutated into a state that never came from the document.
* `Report.max_report_bytes` now delegates to `DMARCator.config.max_report_bytes`. The class-level accessors remain, so existing callers keep working; `Config#max_report_bytes` defaults to 25 MiB and rejects values that are not a positive Integer or nil.

Other changes:

* `DMARCator::XmlHelper` methods are private to including classes, `Record.truncate_error_message` is private, and `DMARCator::Parser` is documented as `@api private`.
* Add an API-contract spec that pins the public surface of every public class, so additions and removals are deliberate.
* Add `SECURITY.md` and document the stability, thread-safety and deprecation policies in the README.

Migration:

| Before | After |
|---|---|
| `report.version == BigDecimal("0.1")` | `report.version == "0.1"` |
| `report.policy.pct = 50` | assign nothing; parsed values are read-only |
| `Report.max_report_bytes = n` | `DMARCator.configure { |c| c.max_report_bytes = n }` |

### 0.11.0 / 2026-10-29

* Add `DMARCator.configure` for process-wide defaults, so a resolver can be set from code instead of only through the `DMARCATOR_DNS` environment variables. A configured resolver takes precedence over the environment, and `DMARCator.reset_configuration!` discards it.
* A configured resolver may be a callable, in which case it is invoked for each lookup. This lets threaded applications use one resolver per lookup instead of sharing a `Resolv::DNS`, which does not serialise concurrent lookups.
* Run CI on macOS 15 as well as Ubuntu 24.04, covering the Socket/OpenSSL and Net::HTTP paths used by the DoT and DoH transports.

### 0.10.0 / 2026-10-29

Breaking changes, taken before 1.0 so the release does not carry them:

* Add `DMARCator::Error` as the base class for every error the library raises. `InvalidRecord`, `InvalidReport` and `ResolutionError` inherit from it, so one `rescue DMARCator::Error` catches all three.
* `InvalidRecord` no longer inherits from `Parslet::ParseFailed`, removing the parser implementation from the public exception contract. Parse failures still expose the underlying parser error as their `cause`.
* Remove the deprecated `DMARCator.query` and `DMARCator::Record.query` aliases. Use `DMARCator.dmarc` and `DMARCator::Record.lookup`.
* Rename `DMARCator::Report::Record` to `DMARCator::Report::Row`, so aggregate rows are not confused with `DMARCator::Record`, the parsed DMARC TXT record.

Migration:

| Before | After |
|---|---|
| `DMARCator.query(domain)` | `DMARCator.dmarc(domain)` |
| `DMARCator::Record.query(domain)` | `DMARCator::Record.lookup(domain)` |
| `DMARCator::Report::Record` | `DMARCator::Report::Row` |
| `rescue Parslet::ParseFailed` | `rescue DMARCator::Error` |

### 0.9.0 / 2026-10-29

* Add `DMARCator.txt_records`, which returns the TXT resource records instead of strings, so callers that cache lookups can read each record's `ttl`. `DMARCator.txt` is now defined in terms of it and behaves the same.

### 0.8.0 / 2026-10-29

* Add `DMARCator.txt`, which returns every TXT record at a name — unfiltered, in response order, with multi-chunk records joined. It accepts service labels such as `_dmarc` and `_domainkey` through a new relaxed `validate_txt_name`, and lets callers detect duplicate DMARC records that `dmarc` deliberately hides.
* Rename the lookup methods after what they return: `DMARCator.dmarc` (was `DMARCator.query`) and `DMARCator::Record.lookup` (was `DMARCator::Record.query`). The old names remain as deprecated aliases and emit no runtime warnings.
* Apply `DMARCATOR_DNS_TIMEOUTS` when the library builds a plaintext resolver, instead of on every lookup. An injected resolver now keeps its own configuration.
* Document the lookup APIs, bulk-scan guidance and deprecations in the README.

### 0.7.0 / 2026-10-29

* Plaintext DNS lookups now fail closed: a lookup failure raises `DMARCator::ResolutionError` instead of being reported as a domain without a DMARC record. Previously a timeout or resolver failure looked like no policy, which failed open. This is a behavior change and applies to every transport.
* DoH responses must use the `application/dns-message` content type (RFC 8484) and are capped at 65,535 bytes.
* `DMARCator::Uri` no longer forwards calls to private methods of the wrapped `URI::MailTo`.
* Remove the unused `XmlHelper#get_int`/`#get_timestamp` helpers and the deprecated `Record.from_txt`.
* Memoize a missing report version instead of recomputing it, and scope spec constants under `DMARCator`.
* Add `changelog_uri` and `documentation_uri` gem metadata, and document that domains must be passed as A-labels.
* Add a CI workflow that runs the specs on the minimum supported Ruby and the current release, loads the gem with warnings enabled, fails on YARD warnings, and builds the gem.

### 0.6.1 / 2026-10-29

* Remove a redundant `attr_reader :sp` that `Record#sp` already overrode, fixing a `method redefined; discarding old sp` warning emitted under `-w` (as CI enables).
* Add tests covering `Record#sp` falling back to `p` when `sp` is omitted.
* Document every report accessor, constant, and public class that YARD previously omitted; documentation coverage is now 100% with no warnings.
* Note the encrypted-transport guarantees in the README security section.
* No functional changes.

### 0.6.0 / 2026-10-28

* Add DNS over HTTPS (RFC 8484) and DNS over TLS (RFC 7858) transports, selected with `DMARCATOR_DNS` (`doh` or `dot`). No provider is bundled and plaintext remains the default.
* Encrypted transports verify TLS certificates, validate the response id, question and TC bit, and follow CNAMEs up to a bounded depth.
* Add `DMARCator::ResolutionError`; encrypted transport failures raise instead of being reported as a missing record.
* Add `DMARCator.default_resolver` and `DMARCator::Resolver.build` for explicit transport configuration.

### 0.5.1 / 2026-10-28

* Point the gem metadata (`homepage`, `source_code_uri`, `bug_tracker_uri`) at the renamed GitHub repository (`dmarc` → `dmarcator`).

### 0.5.0 / 2026-10-28

* Performance: extract each report record in a single pass over its children instead of one XPath query per field (roughly 3x faster `Report#records`).
* Performance: extract report metadata and policy in a single pass.
* Performance: build `Record#reasons` and `Record#auth_results` lazily, so callers that only read scalar fields skip roughly half of record construction.
* Performance: reuse one memoized parser and transform instance, making `Record.parse` roughly 30% faster.
* Add `DMARCator::Report.max_report_bytes` to configure the maximum accepted report size; parsing builds a DOM roughly 13x the input size, so lower it to bound memory.
* Report elements that appear more than once now consistently use the first value, matching prior behavior for records.
* Assign `policy_published` fields explicitly instead of by element name.

### 0.4.2 / 2026-10-28

* Do not raise when the loaded `resolv` version is not a valid gem version; an unparseable version is treated as unknown instead of failing at load time.
* Reject DMARC records larger than 4 KiB (`Parser::MAX_RECORD_BYTES`) before parsing to bound work on hostile input.
* Raise the documented `InvalidRecord`/`InvalidReport` for non-String input instead of `ArgumentError`, `TypeError`, or a silently empty report.

### 0.4.1 / 2026-10-28

* Accept a case-insensitive `mailto:` scheme in `rua`/`ruf` report URIs.
* Fix parsing of `rua`/`ruf` lists that mix valid and invalid URIs.
* Restrict `mailto:` address characters to a safe whitelist.
* Reject underscores in validated domain names.
* Remove the dead Alexa Top 500 scraping task and its fixture.
* Drop the `simplecov` development dependency.
* Housekeeping: remove dead rescue code, fix documentation typos, add frozen string literals, make `Uri` delegation private, and drop the deprecated `gem.test_files`.

### 0.4.0 / 2026-10-26

* Add `strict: true` parsing mode to reject unknown tags and invalid tag values.
* Return `nil` for non-numeric report integers (`count`, `pct`) instead of coercing them to `0`.
* Disable network access (`NONET`) explicitly when parsing XML reports.
* Reject DNS labels with leading or trailing hyphens.
* Set explicit DNS query timeouts.
* Reject XML reports larger than 25 MiB.

### 0.3.1 / 2026-10-26

* Update the gemspec maintainer metadata to list only the fork's author.

### 0.3.0 / 2026-10-26

* Raise `DMARCator::InvalidReport` for malformed XML reports instead of returning an empty report.
* Return `nil` for a non-numeric report `version` instead of raising `ArgumentError`.
* Return `nil` for a non-numeric report timestamp instead of coercing it to the Unix epoch.
* Add `DMARCator::Uri#eql?` and `#hash` for correct Hash/Set semantics.
* Harden `DMARCator.validate_domain` against CVE-2026-80213 (63-octet label limit and 248-octet total limit).
* Warn at load time when the `resolv` gem is affected by CVE-2026-80212/CVE-2026-80213.
* Require Ruby >= 3.3.13 to pick up the Regexp compilation fixes behind GitLab's CVE-2026-89078, CVE-2026-93577, CVE-2026-97229 and CVE-2026-110264.

### 0.2.0 / 2026-10-13

* Added DMARC XML report parsing, ported from the `dmarc_parser` gem by D Salko.
* Added `nokogiri` and `bigdecimal` runtime dependencies.

### 0.1.0 / 2026-10-13

* Forked from the Trail of Bits `dmarc` gem and published as `dmarcator`.
* Renamed the `DMARC` module to `DMARCator` (`require "dmarcator"`).
* Hardened parsing and DNS querying; see the README for details.

### 0.6.0 / 2024-01-24

Entries below this point refer to the original `dmarc` gem.


* {DMARC::Record.parse} now allows trailing whitespace, per DMARC spec.

### 0.5.0 / 2016-06-16

* Added {DMARC::Uri} to represent `mailto:dmarc@example.com!10m` URIs.

### 0.4.0 / 2016-06-10

* Added {DMARC::Record#to_h}.
* Added {DMARC::Record#adkim?}.
* Added {DMARC::Record#aspf?}.
* Added {DMARC::Record#fo?}.
* Added {DMARC::Record#p?}.
* Added {DMARC::Record#pct?}.
* Added {DMARC::Record#rf?}.
* Added {DMARC::Record#ri?}.
* Added {DMARC::Record#rua?}.
* Added {DMARC::Record#ruf?}.
* Added {DMARC::Record#sp?}.

### 0.3.0 / 2015-07-01

* Added {DMARC::Record.query}.
* Added {DMARC::Record#to_s}.
* Added {DMARC::InvalidRecord}.
* Deprecate {DMARC::Record.from_txt}.
* {DMARC::Record#v} now returns `:DMARC1`.
* {DMARC::Record#p} and {DMARC::Record#sp} now return Symbols
* {DMARC::Record#rua} and {DMARC::Record#ruf} will always return Arrays.
* Fixed a bug in {DMARC::Parser} with respect to order of tags.
* {DMARC::Parser::Transform} now coerces URIs into URI objects.

### 0.2.0 / 2014-10-20

* Added `DMARC::Error`.
* Added {DMARC::InvalidRecord}.
* Add support for parsing `fo` tokens.
* Ignore unknown tags instead of raising a parser exception.
* Ignore tags with invalid values instead of raising a parser exception.

### 0.1.0 / 2014-04-25

* Initial release.

