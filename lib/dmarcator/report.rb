# frozen_string_literal: true

require_relative 'config'
require_relative 'internal/xml_guard'
require_relative 'internal/xml_helper'
require_relative 'exceptions'
require_relative 'report/metadata'
require_relative 'report/policy'
require_relative 'report/row'

module DMARCator
  #
  # Represents a parsed DMARC aggregate/forensic XML report.
  #
  # Report XML is treated as untrusted input: DTDs and entity declarations are
  # rejected, network access and entity expansion are disabled, and structural
  # complexity (nodes, depth, records, text and attribute counts) is bounded by
  # {DMARCator.configure} limits before any DOM is built.
  #
  class Report
    include Internal::XmlHelper

    # Default maximum accepted report size in bytes (25 MiB).
    #
    # @deprecated Use {Config::DEFAULT_MAX_REPORT_BYTES}. Removed in 2.0.
    #
    MAX_REPORT_BYTES = Config::DEFAULT_MAX_REPORT_BYTES

    class << self
      #
      # The maximum accepted report size in bytes.
      #
      # @deprecated Use {DMARCator.configure} with `config.max_report_bytes`.
      #   Removed in 2.0.
      #
      # @return [Integer]
      #
      def max_report_bytes
        DMARCator.config.max_report_bytes
      end

      #
      # Sets the maximum accepted report size in bytes.
      #
      # @deprecated Use {DMARCator.configure} with `config.max_report_bytes`.
      #   Removed in 2.0.
      #
      # @param [Integer, nil] value
      #
      # @raise [ArgumentError]
      #   The value is not a positive Integer or nil.
      #
      def max_report_bytes=(value)
        DMARCator.config.max_report_bytes = value
      end
    end

    #
    # Initializes the report from an XML string.
    #
    # @param [String] xml
    #   The raw DMARC XML report.
    #
    # @raise [InvalidReport]
    #   The report is not a String, exceeds
    #   {Config#max_report_bytes}, or is not well-formed XML.
    # @raise [ForbiddenXml]
    #   The report contains a DTD or entity declaration.
    # @raise [ReportTooComplex]
    #   The report exceeds a configured structural limit.
    #
    def initialize(xml)
      unless xml.is_a?(String)
        raise InvalidReport, "DMARC XML report must be a String, got #{xml.class}"
      end

      @xml = xml

      limit = DMARCator.config.max_report_bytes

      if xml.bytesize > limit
        raise InvalidReport, "DMARC XML report exceeds maximum size of #{limit} bytes"
      end

      guard = Internal::XmlGuard.new(xml)
      guard.check!

      @node = guard.document
      @node.remove_namespaces!
    end

    #
    # The report version, as published.
    #
    # Returned as a String because versions are opaque identifiers, not
    # numbers to compute with.
    #
    # @return [String, nil]
    #   The version, or `nil` when it is absent or not numeric.
    #
    def version
      return @version if defined?(@version)

      @version = begin
        value = get_text('feedback/version')
        value = value.strip if value

        value.freeze if value && value.match?(/\A\d+(?:\.\d+)*\z/)
      end
    end

    #
    # The report metadata.
    #
    # @return [Report::Metadata]
    #
    def metadata
      @metadata ||= Metadata.new(@node)
    end

    #
    # The published DMARC policy.
    #
    # @return [Report::Policy]
    #
    def policy
      @policy ||= Policy.new(@node)
    end

    #
    # The report records.
    #
    # @return [Array<Report::Row>]
    #
    def records
      @records ||= @node.xpath('feedback/record').map do |node|
        Row.new(node)
      end.freeze
    end
  end
end
