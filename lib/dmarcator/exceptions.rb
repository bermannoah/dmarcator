# frozen_string_literal: true

module DMARCator
  #
  # Base class for every error raised by this library.
  #
  # Rescuing this catches parse failures, report failures and DNS lookup
  # failures alike.
  #
  # @since 0.10.0
  #
  class Error < StandardError
  end

  #
  # Raised when a DMARC record cannot be parsed.
  #
  # @since 0.2.0
  #
  class InvalidRecord < Error
  end

  #
  # Raised when a DMARC XML report cannot be parsed.
  #
  # @since 0.3.0
  #
  class InvalidReport < Error
  end

  #
  # Raised when a DMARC XML report is well-formed but exceeds a configured
  # structural limit (record count, node count, nesting depth, text length,
  # attribute count, or per-record auth_results/reasons entries).
  #
  # Distinct from {InvalidReport} so an application can audit or reject
  # complexity attacks without treating them as ordinary malformed input.
  #
  # @since 1.3.0
  #
  class ReportTooComplex < Error
  end

  #
  # Raised when a DMARC XML report contains a DTD or entity declaration.
  #
  # DMARC reports never need a DTD or custom entities, so declaring them is
  # rejected outright. This eliminates external-entity (XXE) and
  # entity-expansion (billion-laughs) attacks rather than merely disabling
  # their resolution.
  #
  # @since 1.3.0
  #
  class ForbiddenXml < Error
  end

  #
  # Raised when a DNS transport fails to return a usable answer.
  #
  # This is deliberately distinct from a missing record: a failed lookup must
  # not be mistaken for a domain without a DMARC policy.
  #
  # @since 0.6.0
  #
  class ResolutionError < Error
  end
end
