# frozen_string_literal: true

require 'resolv'
require 'rubygems'

require_relative 'config'
require_relative 'resolver'

module DMARCator
  #
  # Resolv gem versions affected by CVE-2026-80212 and CVE-2026-80213.
  #
  VULNERABLE_RESOLV = [
    Gem::Requirement.new('< 0.3.2'),
    Gem::Requirement.new('>= 0.4.0', '< 0.7.2')
  ].freeze

  #
  # DNS query timeouts in seconds, tried in order.
  #
  # @deprecated No longer used. Plaintext lookups use a single timeout
  #   ({Resolver::Plain}), configurable with `DMARCATOR_DNS_TIMEOUT`.
  #   Removed in 2.0.
  #
  DNS_TIMEOUTS = [2, 4, 8].freeze

  #
  # The maximum length of a textual DNS name, in octets.
  #
  # @since 0.8.0
  #
  MAX_TXT_NAME_LENGTH = 253

  #
  # Determines the version of the loaded `resolv` gem, if available.
  #
  # @return [String, nil]
  #
  def self.resolv_version
    if defined?(Resolv::VERSION)
      Resolv::VERSION
    elsif (spec = Gem.loaded_specs['resolv'])
      spec.version.to_s
    end
  end

  #
  # Determines whether the loaded `resolv` gem is affected by
  # CVE-2026-80212 or CVE-2026-80213.
  #
  # @return [Boolean]
  #
  def self.vulnerable_resolv?
    version = resolv_version
    return false unless version

    begin
      parsed = Gem::Version.new(version)
    rescue ArgumentError
      # A non-semver version string means we cannot tell; do not warn.
      return false
    end

    VULNERABLE_RESOLV.any? do |requirement|
      requirement.satisfied_by?(parsed)
    end
  end

  #
  # Validates a domain before using it in a DNS query.
  #
  # Rejects underscores and enforces the DNS length and label limits, so this
  # is the validator for registrable domains rather than arbitrary DNS names.
  # {dmarc} adds the `_dmarc.` prefix; use {validate_txt_name} for service
  # labels.
  #
  # @param [String] domain
  #   The domain to validate.
  #
  # @return [String]
  #   The validated domain.
  #
  # @raise [ArgumentError]
  #   The domain is not a syntactically valid DNS name.
  #
  def self.validate_domain(domain)
    unless domain.is_a?(String) && !domain.empty? &&
           domain.length <= 248 &&
           !domain.start_with?('.') &&
           !domain.include?('..') &&
           !domain.match?(/[^A-Za-z0-9.-]/) &&
           domain.split('.').all? { |label| label.length <= 63 && !label.start_with?('-') && !label.end_with?('-') }
      raise ArgumentError, "invalid domain: #{domain.inspect}"
    end

    domain
  end

  #
  # Validates an arbitrary DNS name used for a TXT lookup.
  #
  # Unlike {validate_domain}, service labels such as `_dmarc` and `_domainkey`
  # are allowed, so names may contain underscores. Length and label limits are
  # still enforced so hostile input cannot reach the resolver unbounded.
  #
  # @param [String] name
  #   The DNS name to validate.
  #
  # @return [String]
  #   The validated name.
  #
  # @raise [ArgumentError]
  #   The name is not a syntactically valid DNS name.
  #
  # @since 0.8.0
  #
  def self.validate_txt_name(name)
    unless name.is_a?(String) && !name.empty? &&
           name.length <= MAX_TXT_NAME_LENGTH &&
           !name.start_with?('.') &&
           !name.include?('..') &&
           name.match?(/\A[A-Za-z0-9._-]+\z/) &&
           name.split('.').all? { |label| label.length <= 63 && !label.start_with?('-') && !label.end_with?('-') }
      raise ArgumentError, "invalid TXT name: #{name.inspect}"
    end

    name
  end

  #
  # The default resolver: a {configure}d one, or one built from the
  # environment.
  #
  # A configured resolver may be an object or a callable; a callable is called
  # for each lookup, which is what threaded applications should use.
  #
  # @return [Resolv::DNS, Resolver::DoH, Resolver::DoT]
  #
  # @raise [ArgumentError]
  #   The configured transport or its settings are invalid.
  #
  # @since 0.6.0
  #
  def self.default_resolver
    configured = config.resolver

    return configured.call if configured.respond_to?(:call)

    configured || Resolver.build
  end

  #
  # Looks up every TXT record published at a DNS name.
  #
  # Records are returned exactly as published: unfiltered, in response order,
  # and with multi-chunk records joined. Interpreting them (SPF, DKIM, DMARC,
  # domain verification) is left to the caller. Use this when the individual
  # records matter, for example to detect that a domain publishes more than
  # one DMARC record.
  #
  # @param [String] name
  #   The DNS name to look up, such as `example.com`, `_dmarc.example.com`, or
  #   `s1._domainkey.example.com`.
  #
  # @param [Resolv::DNS, Resolver::DoH, Resolver::DoT] resolver
  #   The resolver to use. When omitted, one is built from `DMARCATOR_DNS`.
  #   An injected resolver keeps its own configuration.
  #
  # @return [Array<String>]
  #   The TXT records, or an empty array when the name has none. NXDOMAIN and
  #   NODATA are indistinguishable here.
  #
  # @raise [ResolutionError]
  #   The lookup failed. A failure is never reported as an empty result, so a
  #   blocked or degraded resolver cannot be mistaken for an absent record.
  #
  # @raise [ArgumentError]
  #   The name is not a syntactically valid DNS name, or the injected
  #   resolver would report a timeout as an absent record.
  #
  # @note Names must be ASCII: pass punycode (A-labels) rather than Unicode.
  #
  # @since 0.8.0
  #
  def self.txt(name, resolver: default_resolver)
    txt_records(name, resolver: resolver).map { |record| record.strings.join }
  end

  #
  # Looks up every TXT record at a DNS name, returning the resource records
  # themselves.
  #
  # Like {txt}, but without flattening to strings. The records expose
  # `strings` and `ttl`, which matters when caching results: use
  # `record.ttl` to decide how long an answer may be reused.
  #
  # @param [String] name
  #   The DNS name to look up.
  #
  # @param [Resolv::DNS, Resolver::DoH, Resolver::DoT] resolver
  #   The resolver to use. When omitted, one is built from `DMARCATOR_DNS`.
  #   An injected resolver keeps its own configuration.
  #
  # @return [Array<Resolv::DNS::Resource::IN::TXT>]
  #   The records, or an empty array when the name has none. NXDOMAIN and
  #   NODATA are indistinguishable here.
  #
  # @raise [ResolutionError]
  #   The lookup failed. A failure is never reported as an empty result.
  #
  # @raise [ArgumentError]
  #   The name is not a syntactically valid DNS name, or the injected
  #   resolver would report a timeout as an absent record.
  #
  # @note Names must be ASCII: pass punycode (A-labels) rather than Unicode.
  #
  # @since 0.9.0
  #
  def self.txt_records(name, resolver: default_resolver)
    lookup_txt(validate_txt_name(name), resolver: resolver)
  end

  #
  # Looks up the DMARC record text published for a domain.
  #
  # This is the lowest-cost DMARC path: one TXT lookup and no parsing. Use it
  # for bulk scans, and call {Record.parse} only on records you care about.
  #
  # @param [String] domain
  #   The domain to look up DMARC for.
  #
  # @param [Resolv::DNS, Resolver::DoH, Resolver::DoT] resolver
  #   The resolver to use. When omitted, one is built from `DMARCATOR_DNS`.
  #
  # @return [String, nil]
  #   The DMARC record text, or `nil` when the domain publishes none or
  #   publishes more than one (per RFC 7489 §6.6.3). Use {txt} to see every
  #   record, including duplicates.
  #
  # @raise [ResolutionError]
  #   The lookup failed.
  #
  # @raise [ArgumentError]
  #   The domain is not a syntactically valid DNS name, or the injected
  #   resolver would report a timeout as an absent record.
  #
  # @since 0.8.0
  #
  def self.dmarc(domain, resolver: default_resolver)
    name = "_dmarc.#{validate_domain(domain)}"

    # Per RFC 7489 §6.6.3, use the TXT record beginning with "v=DMARC1".
    # If multiple DMARC records exist, treat the domain as having none.
    dmarc_records = lookup_txt(name, resolver: resolver).map do |record|
      record.strings.join
    end.select do |text|
      text.start_with?('v=DMARC1')
    end

    dmarc_records.first if dmarc_records.one?
  end

  #
  # Looks up the TXT records at an already-validated name.
  #
  # Shared by {txt}, {txt_records} and {dmarc} so they use one transport path.
  #
  # @param [String] name
  #
  # @param [Resolv::DNS, Resolver::DoH, Resolver::DoT] resolver
  #
  # @return [Array<Resolv::DNS::Resource::IN::TXT>]
  #
  # @raise [ResolutionError]
  #
  # @api private
  #
  def self.lookup_txt(name, resolver:)
    ensure_fail_closed!(resolver)

    # With a fail-closed resolver, Resolv returns an empty result for NXDOMAIN
    # and raises for timeouts and other failures, so any exception here is a
    # transport failure, not an absent record.
    begin
      records = resolver.getresources(name, Resolv::DNS::Resource::IN::TXT)
    rescue Resolv::ResolvError => error
      raise ResolutionError, "DNS TXT lookup failed for #{name}: #{error.message}"
    end

    records
  end
  private_class_method :lookup_txt

  #
  # Determines whether a resolver reports a timeout instead of returning an
  # empty answer.
  #
  # `Resolv::DNS` treats a complete timeout as an empty answer unless it was
  # constructed with `raise_timeout_errors: true`. The flag is only settable
  # through the constructor and `Resolv` exposes no reader for it, so it is
  # read from the retained configuration.
  #
  # @param [Object] resolver
  #
  # @return [Boolean]
  #
  # @api private
  #
  def self.resolv_fails_closed?(resolver)
    return true unless resolver.is_a?(Resolv::DNS)

    config = resolver.instance_variable_get(:@config)
    return false unless config

    info = config.instance_variable_get(:@config_info)
    return false unless info.is_a?(Hash)

    !!info[:raise_timeout_errors]
  end
  private_class_method :resolv_fails_closed?

  #
  # Rejects a resolver that would report a failed lookup as an absent record.
  #
  # @param [Object] resolver
  #
  # @raise [ArgumentError]
  #   The resolver is a `Resolv::DNS` that does not raise on timeout.
  #
  # @api private
  #
  def self.ensure_fail_closed!(resolver)
    return if resolv_fails_closed?(resolver)

    raise ArgumentError,
          'a Resolv::DNS resolver swallows timeout errors unless constructed ' \
          'with raise_timeout_errors: true, so a failed lookup cannot be ' \
          'distinguished from a name with no records; use ' \
          'Resolv::DNS.new(raise_timeout_errors: true) or ' \
          'DMARCator::Resolver::Plain'
  end
  private_class_method :ensure_fail_closed!
end

if DMARCator.vulnerable_resolv?
  warn "dmarcator: resolv #{DMARCator.resolv_version} is affected by " \
       "CVE-2026-80212 and CVE-2026-80213; upgrade to resolv >= 0.7.2 " \
       "(or >= 0.3.2 on Ruby 3.3)"
end
