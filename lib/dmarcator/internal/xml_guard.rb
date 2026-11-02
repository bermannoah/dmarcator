# frozen_string_literal: true

require 'nokogiri'

require_relative '../config'
require_relative '../exceptions'

module DMARCator
  #
  # Implementation details of the library. Nothing here is covered by the
  # 1.0 compatibility promise.
  #
  # @api private
  #
  module Internal
    #
    # Hardens DMARC XML report parsing against hostile input.
    #
    # A DMARC report never needs a DTD or custom entities, so declarations are
    # rejected outright, and libxml2 is configured to disable everything that
    # could fetch or expand them. Structural complexity is bounded with a
    # streaming reader pass before any DOM is built, so a report that exceeds a
    # limit is rejected without first allocating a tree for it.
    #
    # Ruby's `Timeout` is deliberately not used here: it cannot reliably
    # interrupt libxml2's C-level parsing. Callers that need a hard wall-clock
    # bound must run the parse in a subprocess with resource limits; the limits
    # enforced here bound the work the C parser is asked to do.
    #
    # @api private
    #
    class XmlGuard
      # DTD and entity declarations, which are never legitimate in a report.
      #
      # Matched case-insensitively against the raw bytes as a cheap first line
      # of defence; the streaming pass also rejects the parsed
      # `DOCTYPE`/`ENTITY` nodes, which covers encodings this byte scan cannot
      # see (for example UTF-16).
      FORBIDDEN_DECLARATION = /<!doctype|<!entity/i

      #
      # Parse options shared by the streaming reader and the DOM parser.
      #
      # * `nonet` forbids network access (external entities are never fetched).
      # * `nonoent`, `nodtdload` and `nodtdattr` keep entity substitution and
      #   DTD loading disabled.
      # * `nohuge` keeps libxml2's own hardcoded limits in force.
      # * The base options are strict (`ParseOptions.new`), so malformed input
      #   is reported rather than silently recovered.
      #
      # @return [Nokogiri::XML::ParseOptions]
      #
      def self.parse_options
        Nokogiri::XML::ParseOptions.new.tap do |options|
          options.nonet
          options.nonoent
          options.nodtdload
          options.nodtdattr
          options.nohuge
        end
      end

      #
      # @param [String] xml
      #   The raw DMARC XML report.
      # @param [Config] config
      #   The configuration whose limits are enforced.
      #
      def initialize(xml, config = DMARCator.config)
        @xml = xml
        @config = config
      end

      #
      # Rejects forbidden declarations and enforces structural limits without
      # building a DOM.
      #
      # @return [XmlGuard] self
      #
      # @raise [ForbiddenXml]
      #   The report contains a DTD or entity declaration.
      # @raise [ReportTooComplex]
      #   The report exceeds a configured structural limit.
      # @raise [InvalidReport]
      #   The report is not well-formed XML or its encoding is malformed.
      #
      def check!
        reject_forbidden_declarations!
        enforce_structural_limits!
        self
      end

      #
      # Parses the report into a hardened DOM.
      #
      # @return [Nokogiri::XML::Document]
      #
      # @raise [InvalidReport]
      #   The report is not well-formed XML or its encoding is malformed.
      #
      def document
        @document ||= parse_document
      end

      private

      def reject_forbidden_declarations!
        haystack = if @xml.encoding.ascii_compatible? && @xml.valid_encoding?
                     @xml
                   else
                     @xml.b
                   end

        return unless haystack.match?(FORBIDDEN_DECLARATION)

        raise ForbiddenXml, 'DMARC XML reports must not contain a DTD or entity declaration'
      end

      def enforce_structural_limits!
        reader = Nokogiri::XML::Reader(@xml, nil, nil, self.class.parse_options)

        nodes = 0
        records = 0
        attributes = 0

        while reader.read
          case reader.node_type
          when Nokogiri::XML::Reader::TYPE_DOCUMENT_TYPE,
               Nokogiri::XML::Reader::TYPE_ENTITY
            raise ForbiddenXml, 'DMARC XML reports must not contain a DTD or entity declaration'
          when Nokogiri::XML::Reader::TYPE_ELEMENT
            nodes += 1
            records += 1 if reader.name == 'record'
            attributes += reader.attribute_count

            enforce(:max_xml_nodes, nodes)
            enforce(:max_report_records, records)
            enforce(:max_xml_depth, reader.depth + 1)
            enforce(:max_xml_attributes, attributes)
          when Nokogiri::XML::Reader::TYPE_TEXT,
               Nokogiri::XML::Reader::TYPE_CDATA,
               Nokogiri::XML::Reader::TYPE_WHITESPACE,
               Nokogiri::XML::Reader::TYPE_SIGNIFICANT_WHITESPACE,
               Nokogiri::XML::Reader::TYPE_COMMENT,
               Nokogiri::XML::Reader::TYPE_PROCESSING_INSTRUCTION,
               Nokogiri::XML::Reader::TYPE_ENTITY_REFERENCE
            nodes += 1
            enforce(:max_xml_nodes, nodes)

            value = reader.value
            enforce(:max_text_length, value.bytesize) if value
          end
        end
      rescue Nokogiri::XML::SyntaxError => e
        raise InvalidReport, "invalid DMARC XML report: #{e.message}"
      end

      def enforce(setting, value)
        limit = @config.public_send(setting)
        return unless value > limit

        raise ReportTooComplex, "DMARC XML report exceeds #{setting} of #{limit}"
      end

      def parse_document
        document = Nokogiri::XML.parse(@xml, nil, nil, self.class.parse_options)

        document
      rescue Nokogiri::XML::SyntaxError => e
        raise InvalidReport, "invalid DMARC XML report: #{e.message}"
      end
    end
  end
end
