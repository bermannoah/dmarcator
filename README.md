# DMARCator

[![Gem Version](https://badge.fury.io/rb/dmarcator.svg)](https://badge.fury.io/rb/dmarcator)
[![YARD Docs](https://img.shields.io/badge/yard-docs-blue.svg)](https://rubydoc.info/gems/dmarcator)

DMARCator is a Ruby library for parsing and querying [DMARC] records.

> **DMARCator is a fork of the [`dmarc`][dmarc-gem] gem, originally created by
> Davis Gallinghouse at [Trail of Bits].** It keeps the original MIT license and
> credits its authors, but ships under a new name with additional hardening and
> a stricter parser. See [Acknowledgments](#acknowledgments) below.

[DMARC] policies are published as DNS TXT records at `_dmarc.<domain>`. This
library parses those records into a structured `DMARCator::Record`, queries them
over DNS, and parses the XML aggregate
reports those policies generate.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "dmarcator"
```

And then execute:

```sh
bundle install
```

Or install it yourself:

```sh
gem install dmarcator
```

The gem is loaded via:

```ruby
require "dmarcator"
```

## Example

Parse a DMARC record:

```ruby
require "dmarcator"

record = DMARCator::Record.parse(
  "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com; fo=1"
)

record.v
# => :DMARC1

record.p
# => :reject

record.adkim
# => :r

record.aspf
# => :r

record.fo
# => ["1"]

record.pct
# => 100

record.rf
# => :afrf

record.ri
# => 86400

record.rua
# => [#<DMARCator::Uri ... @uri=#<URI::MailTo mailto:d@rua.agari.com>, @size=nil, @unit=nil>]

record.ruf
# => [#<DMARCator::Uri ... @uri=#<URI::MailTo mailto:d@ruf.agari.com>, @size=nil, @unit=nil>]

record.sp
# => :reject
```

Query the DMARC record for a domain:

```ruby
record = DMARCator::Record.lookup("twitter.com")
# => #<DMARCator::Record ... @p=:reject, @rua=[...], ...>
```

Domains must be ASCII (A-labels): pass punycode such as
`xn--mnchen-3ya.de` rather than `münchen.de`. A lookup failure raises
`DMARCator::ResolutionError`; `nil` only means the domain genuinely has no
DMARC record.

## Lookup APIs

The lookup methods are named after what they return:

| Method | Returns | Cost |
|---|---|---|
| `DMARCator.txt_records(name)` | `Array<Resolv::DNS::Resource::IN::TXT>` — the records themselves | one lookup |
| `DMARCator.txt(name)` | `Array<String>` — every TXT record at `name` | one lookup |
| `DMARCator.dmarc(domain)` | `String` — the DMARC record text, or `nil` | one lookup |
| `DMARCator::Record.lookup(domain)` | `Record` — parsed | one lookup + parse (~0.4 ms) |
| `DMARCator::Record.parse(text)` | `Record` — parsed from a string | parse only |

`DMARCator.txt` is the primitive: unfiltered, in response order, multi-chunk
records joined. It works for any TXT name, including `_dmarc.` and
`_domainkey.` labels, and leaves interpretation to the caller:

```ruby
DMARCator.txt("_dmarc.example.com")
# => ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]

DMARCator.txt("example.com")
# => ["v=spf1 include:_spf.example.com -all", "google-site-verification=abc"]

DMARCator.txt("s1._domainkey.example.com")
# => []
```

Because it returns every record, it is also how you detect misconfiguration
that `DMARCator.dmarc` deliberately hides per RFC 7489 §6.6.3:

```ruby
records = DMARCator.txt("_dmarc.#{domain}").select { |t| t.start_with?("v=DMARC1") }
case records.length
when 0 then :none
when 1 then :ok
else :duplicate  # more than one DMARC record breaks enforcement
end
```

Use `DMARCator.txt_records` when you need the DNS TTL, for example to cache
lookups in a database:

```ruby
records = DMARCator.txt_records("_dmarc.#{domain}")
records.each do |record|
  record.strings.join  # the TXT value
  record.ttl           # seconds the answer may be cached
end
```

All of these accept an injected resolver, and an injected resolver keeps its
own configuration (timeouts are only applied to resolvers the library builds):

```ruby
resolver = DMARCator::Resolver::DoH.new(url: "https://dns.example/dns-query")
DMARCator.txt("_dmarc.example.com", resolver: resolver)
DMARCator.txt_records("_dmarc.example.com", resolver: resolver)
DMARCator.dmarc("example.com", resolver: resolver)
DMARCator::Record.lookup("example.com", resolver: resolver)
```

### Bulk lookups

`DMARCator.dmarc` is the cheapest DMARC path — one lookup, no parsing. For a
scan over many domains:

```ruby
resolver = DMARCator.default_resolver   # build once, not per domain
domains.each do |domain|
  record = DMARCator.dmarc(domain, resolver: resolver)
  # parse only when you need the fields
end
```

Notes for large scans: `Record.lookup` adds a parse per domain (~0.4 ms, far
more than the lookup on a fast resolver); each lookup opens its own TCP
connection, so keep one resolver per thread when parallelising; and DoT/DoH add
a TLS handshake per lookup, so plaintext is the better choice for bulk work.

### SPF and DKIM

The TXT primitives also cover the other two records a checker needs. There is
no record-type-specific API, because the semantics belong to the caller:

```ruby
DMARCator.txt("example.com")                # SPF (RFC 7208)
DMARCator.txt("s1._domainkey.example.com")  # DKIM (RFC 6376)
```

Both need the raw list rather than a single value: more than one SPF record is
a `permerror`, and DKIM keys can be duplicated, rotated or revoked (`p=`). A
helper returning "the" record would hide exactly those conditions. DKIM is also
per-selector and selectors cannot be enumerated, so any convenience method would
have to take a selector and would only build the name above.

## Configuration

Process-wide defaults can be set from code, and take precedence over the
`DMARCATOR_DNS` environment variables:

```ruby
DMARCator.configure do |config|
  config.resolver = DMARCator::Resolver::DoH.new(url: "https://dns.example/dns-query")
  config.max_report_bytes = 5 * 1024 * 1024

  # XML report complexity limits (defaults shown)
  config.max_report_records = 10_000
  config.max_xml_nodes = 100_000
  config.max_xml_depth = 50
  config.max_text_length = 1 * 1024 * 1024
  config.max_xml_attributes = 100_000
  config.max_auth_results = 100
  config.max_reasons = 100
end
```

A resolver object is shared by every thread, so threaded applications should
configure a factory instead:

```ruby
DMARCator.configure do |config|
  config.resolver = -> { Resolv::DNS.new }
end
```

`DMARCator.reset_configuration!` discards configured values, which is useful in
tests. Passing `resolver:` to a lookup still overrides both the configured
default and the environment.

## Strict parsing

By default, unknown tags and tags with invalid values are ignored. Pass
`strict: true` to reject them instead:

```ruby
DMARCator::Record.parse("v=DMARC1; p=none; pct=abc", strict: true)
# => DMARCator::InvalidRecord: invalid DMARC tag value: "pct=abc"
```

## Parsing XML reports

Parse a DMARC aggregate/forensic report:

```ruby
report = DMARCator::Report.new(xml_string)

report.version
# => "0.1"

report.metadata.org_name
# => "google.com"

report.policy.domain
# => "opserv.io"

report.records.first.source_ip
# => "209.85.220.69"
```

## DNS transport

By default, lookups use plain DNS over **TCP** (`DMARCator::Resolver::Plain`).
Encrypted transports can be selected with environment variables; no DNS provider
is baked in:

```sh
# DNS over HTTPS (RFC 8484)
export DMARCATOR_DNS=doh
export DMARCATOR_DOH_URL=https://cloudflare-dns.com/dns-query
export DMARCATOR_DOH_IP=1.1.1.1          # optional: pin the endpoint

# DNS over TLS (RFC 7858)
export DMARCATOR_DNS=dot
export DMARCATOR_DOT_SERVER=1.1.1.1:853
export DMARCATOR_DOT_SNI=cloudflare-dns.com   # optional: name to verify

# optional, both transports (seconds, default 5)
export DMARCATOR_DNS_TIMEOUT=5
```

Certificates are always verified. `DMARCATOR_DOH_IP` pins the address so the
DoH endpoint does not have to be resolved first; TLS still verifies the URL's
hostname. `DMARCATOR_DNS_TIMEOUT` applies to every transport, including
plaintext (default 5 seconds).

Plaintext uses TCP rather than UDP deliberately. `Resolv::DNS` reads UDP replies
into a 512-byte buffer, so a larger answer cannot be decoded, is discarded, and
the resulting timeout is swallowed — meaning any TXT set over 512 bytes (common
for SPF, and for domains with several DKIM keys) came back as an empty result,
indistinguishable from "no records published". TCP has no such limit, and
failures raise `DMARCator::ResolutionError`.

Encrypted transports fail closed: a transport failure raises
`DMARCator::ResolutionError` instead of being reported as a domain without a
DMARC record. This applies to every transport, including plaintext —
`Resolv` returns an empty result for NXDOMAIN and raises for timeouts and
other failures, so a failed lookup is never mistaken for an absent record.
Plaintext remains the default because forcing a public resolver breaks private
and split-horizon zones, and some networks block port 853 or public resolvers.

A resolver can also be built explicitly:

```ruby
resolver = DMARCator::Resolver::DoH.new(url: "https://dns.example/dns-query")
record   = DMARCator::Record.lookup("example.com", resolver: resolver)
```

## Stability

The public API is pinned by a contract spec in the test suite: the module
methods, constants and per-class public methods it asserts are the supported
surface. Anything marked `@api private` in the documentation — the parser, the
XML helper, the internal resolver plumbing — may change in a minor release.

### Thread safety

* `DMARCator::Record`, `DMARCator::Report` and the parsed value objects are
  read-only after construction and safe to share between threads.
* The memoized parser and transform are shared, and safe for concurrent use.
* Resolvers are not necessarily safe for concurrent lookups: each lookup opens
  its own connection, but `Resolv::DNS` (if you inject one) does not serialise
  queries. Use one resolver per thread, or configure a factory with
  `DMARCator.configure` so each lookup builds its own.
* `DMARCator.configure` mutates process-wide state. Call it during boot rather
  than per request.

### Deprecations

A method is deprecated in a minor release by documentation only — no runtime
warnings, so nothing is added to application logs. Deprecated methods are
removed in the next major release.

### Ruby support

The minimum is Ruby 3.3.13, the first release in that series with the regular
expression fixes the library requires. Dropping support for a Ruby series is
the one documented exception to the no-breaking-changes promise: it is announced
in a minor release and removed in the next major.

## Security

DMARC records and XML reports are treated as untrusted input. See
[SECURITY.md](https://github.com/bermannoah/dmarcator/blob/main/SECURITY.md)
for the reporting policy and scope.

* XML reports are treated as hostile: DTDs and entity declarations are
  rejected outright (`DMARCator::ForbiddenXml`), and parsing disables network
  access, entity substitution, DTD loading, and libxml2's `HUGE` relaxation.
  External-entity (XXE) and entity-expansion (billion-laughs) attacks are
  therefore impossible rather than merely mitigated. A report must have a
  `<feedback>` root element; arbitrary well-formed XML is rejected with
  `DMARCator::InvalidReport`.
* Report structural complexity is bounded before any DOM is built. Every limit
  below — including the per-record `auth_results`/`reason` limits — is enforced
  by a streaming pre-check, so a report that exceeds a configured limit raises
  `DMARCator::ReportTooComplex` before a DOM is allocated:

  | Setting | Default | Bounds |
  |---|---|---|
  | `max_report_bytes` | 25 MiB | input size |
  | `max_report_records` | 10,000 | `record` elements |
  | `max_xml_nodes` | 100,000 | element/text/comment nodes |
  | `max_xml_depth` | 50 | element nesting depth |
  | `max_text_length` | 1 MiB | bytes per text node |
  | `max_xml_attributes` | 100,000 | attribute nodes |
  | `max_auth_results` | 100 | `auth_results` entries per record |
  | `max_reasons` | 100 | `reason` entries per record |

  Lower them to bound memory and CPU for reports from untrusted sources:

  ```ruby
  DMARCator.configure { |config| config.max_report_bytes = 5 * 1024 * 1024 }
  ```

  These limits are not the outer boundary. They bound the work the C parser is
  asked to do, but a libxml2 bug can still bypass Ruby-level checks. Applications
  parsing reports from untrusted sources should still run the parse in an
  isolated worker or subprocess with its own resource limits.
* A warning is emitted at load time if the bundled `resolv` gem is affected by
  CVE-2026-80212/CVE-2026-80213.
* Domain names are validated before resolution (labels ≤ 63 octets, total ≤
  248 octets, no leading/trailing hyphens).
* Optional [DNS over HTTPS and DNS over TLS](#dns-transport) transports verify
  TLS certificates and fail closed: a transport failure raises
  `DMARCator::ResolutionError` rather than being reported as a domain without a
  DMARC record, so a blocked or downgraded lookup can never silently enforce no
  policy. Plaintext lookups fail closed the same way. DoH responses must be
  `application/dns-message` and are capped at 65,535 bytes.

## Requirements

* [Ruby] >= 3.3.13
* [nokogiri] >= 1.10

## Testing

To run the RSpec tests:

```sh
rake spec
```

### Record parser corpus

`spec/support/record_corpus.txt` holds representative records — real-world
published records and edge cases — and `spec/support/record_corpus.json` the
outcomes they produced when the corpus was last accepted. The suite replays both
in lenient and strict mode, so a parser change that alters how any of them parses
fails with a diff.

If such a change is intentional, regenerate the file and review the JSON diff in
the commit:

```sh
ruby -Ilib script/generate_record_corpus.rb
```

## Releasing

Every published version must have an annotated tag pointing at the commit that
was built, so a gem can always be traced back to its source:

```sh
# 1. Bump VERSION in lib/dmarcator/version.rb and add a ChangeLog entry.
# 2. Commit the release.
git commit -am "Bump version to X.Y.Z"

# 3. Tag that commit before building anything, with release notes in the
#    tag message. Repeating -m adds blank-line-separated paragraphs.
git tag -a vX.Y.Z \
    -m "dmarcator X.Y.Z" \
    -m "Summary of the release, including behaviour changes and upgrade notes." \
    -m "See ChangeLog.md for the itemized list."

# 4. Push the commit and its tags.
git push origin main --follow-tags

# 5. Build and publish from the tagged checkout.
gem build dmarc.gemspec
gem push dmarcator-X.Y.Z.gem
```

The tag message is the release note: it is what `git show vX.Y.Z` prints, so
put the highlight summary and any upgrade guidance there. Write it before step
4, because a pushed tag message cannot be changed without force-pushing the tag.

Tag before publishing, never after: a tag without a published gem, or a gem
without a tag, makes the two hard to reconcile later.

## License

This project is released under the MIT License. See the [LICENSE.txt] file for
details.

## Acknowledgments

DMARCator is a fork of [`dmarc`][dmarc-gem], a DMARC record parser created by
Davis Gallinghouse at [Trail of Bits] and released under the MIT License.

This fork renames the `DMARC` module to `DMARCator` (loaded via
`require "dmarcator"`) while keeping the original API shape, and adds:

* strict `mailto:`-only handling for `rua`/`ruf` report URIs,
* validation for required and ranged tags (`p`, `pct`, `ri`) and duplicate tags,
* a DNS query path that selects the `v=DMARC1` TXT record per RFC 7489,
* hardened packaging and test fixtures.

The DMARC XML report parser is ported from [`dmarc_parser`][dmarc-parser-gem],
created by D Salko and released under the MIT License.

[DMARC]: https://www.rfc-editor.org/rfc/rfc7489
[dmarc-gem]: https://rubygems.org/gems/dmarc
[dmarc-parser-gem]: https://rubygems.org/gems/dmarc_parser
[Trail of Bits]: https://www.trailofbits.com
[Ruby]: https://www.ruby-lang.org
[nokogiri]: https://nokogiri.org
[LICENSE.txt]: LICENSE.txt
