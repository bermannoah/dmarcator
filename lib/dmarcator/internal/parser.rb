# frozen_string_literal: true

require 'strscan'
require 'uri'

require_relative '../exceptions'
require_relative '../uri'

module DMARCator
  #
  # Implementation details of the library. Nothing here is covered by the
  # 1.0 compatibility promise.
  #
  # @api private
  #
  module Internal
    #
    # Parses DMARC records (RFC 7489 section 6.4).
    #
    # A hand-written parser rather than a parser-combinator grammar: the
    # language is small, and this keeps record parsing allocation-light and
    # free of a runtime dependency.
    #
    # @see https://www.rfc-editor.org/rfc/rfc7489#section-6.4
    #
    # @api private
    #
    class Parser
      # Maximum accepted DMARC record size in bytes. Real records are far
      # smaller; the cap bounds parsing work on hostile input.
      MAX_RECORD_BYTES = 4096

      # Maximum length of error messages echoed from untrusted input.
      MAX_ERROR_MESSAGE_LENGTH = 300

      # Tags whose value is one keyword from a fixed set.
      KEYWORD_TAGS = {
        'p' => %w[none quarantine reject],
        'sp' => %w[none quarantine reject],
        'adkim' => %w[r s],
        'aspf' => %w[r s],
        'rf' => %w[afrf iodef]
      }.freeze

      # Tags whose value is a decimal number of at most N digits.
      DIGIT_TAGS = { 'ri' => 10, 'pct' => 3 }.freeze

      # Tags whose value is a list of mailto URIs.
      URI_TAGS = %w[rua ruf].freeze

      # Every tag the parser understands.
      KNOWN_TAGS = (KEYWORD_TAGS.keys + DIGIT_TAGS.keys + %w[fo] + URI_TAGS).freeze

      # The `v=` tag, which may only appear first.
      #
      # RFC 7489 spells the version with ABNF quoted strings and numeric
      # terminals, so the tag name `v` is case-insensitive (RFC 5234) while the
      # version string `DMARC1` is exact.
      VERSION = /\A[vV][ \t]*=[ \t]*DMARC1\z/

      # Characters allowed in a mailto local part and domain.
      ADDRESS = /[A-Za-z0-9._%+-]+@[A-Za-z0-9._%+-]+/

      # Characters allowed between tags.
      WSP = /[ \t]*/

      class << self
        #
        # Parses a DMARC record.
        #
        # @param [String] record
        #   The raw DMARC record to parse.
        #
        # @param [Boolean] strict (false)
        #   When `true`, raise on unknown tags or invalid tag values instead
        #   of silently ignoring them.
        #
        # @return [Hash{Symbol => Object}]
        #
        # @raise [InvalidRecord]
        #   The record is malformed, is too large, or (in strict mode)
        #   contains an unknown tag or invalid tag value.
        #
        def parse(record, strict: false)
          unless record.is_a?(String)
            raise InvalidRecord, "DMARC record must be a String, got #{record.class}"
          end

          if record.bytesize > MAX_RECORD_BYTES
            raise InvalidRecord, "DMARC record exceeds maximum size of #{MAX_RECORD_BYTES} bytes"
          end

          # Malformed or non-ASCII-compatible encodings make the regular
          # expressions below raise ArgumentError or Encoding::CompatibilityError
          # instead of InvalidRecord, which would escape `rescue DMARCator::Error`.
          unless record.encoding.ascii_compatible?
            raise InvalidRecord,
                  "DMARC record must be ASCII-compatible text, got #{record.encoding}"
          end

          unless record.valid_encoding?
            raise InvalidRecord, "DMARC record is not valid #{record.encoding} text"
          end

          tags = { v: :DMARC1 }

          split(record).each do |segment|
            status, key, value = parse_segment(segment)

            case status
            when :ok
              raise InvalidRecord, "duplicate DMARC tag: #{key}" if tags.key?(key)

              tags[key] = value
            when :version
              raise InvalidRecord, 'duplicate DMARC version tag'
            when :unknown
              if strict
                raise InvalidRecord, "unknown DMARC tag: #{truncate(segment).inspect}"
              end
            when :empty
              if strict
                raise InvalidRecord, "empty DMARC tag value: #{truncate(segment).inspect}"
              end
            when :invalid
              if strict
                raise InvalidRecord, "invalid DMARC tag value: #{truncate(segment).inspect}"
              end
            end
          end

          validate!(tags)
        end

        private

        #
        # Splits a record into tag segments, validating the version tag.
        #
        def split(record)
          separator = record.index(';')
          version = (separator ? record[0, separator] : record).sub(/[ \t]+\z/, '')
          rest = separator ? record[(separator + 1)..] : ''

          unless version.match?(VERSION)
            raise InvalidRecord, "invalid DMARC record: #{truncate(record).inspect}"
          end

          # At most one trailing separator, plus optional surrounding space.
          rest = rest.sub(/[ \t]+\z/, '').sub(/;[ \t]*\z/, '').sub(/[ \t]+\z/, '')

          return [] if rest.empty?

          rest.split(';', -1).map do |segment|
            segment = segment.sub(/\A[ \t]+/, '').sub(/[ \t]+\z/, '')

            if segment.empty?
              raise InvalidRecord, "invalid DMARC record: #{truncate(record).inspect}"
            end

            segment
          end
        end

        #
        # Classifies and parses one `tag=value` segment.
        #
        # @return [Array(Symbol, Symbol, Object), Array(Symbol)]
        #
        def parse_segment(segment)
          name, value = segment.split('=', 2)

          return [:unknown] if value.nil?

          name = name.sub(/[ \t]+\z/, '').sub(/\A[ \t]+/, '').downcase(:ascii)
          value = value.sub(/\A[ \t]+/, '').sub(/[ \t]+\z/, '')

          # The version tag may only appear first, so a second one is a
          # duplicate whatever its value.
          return [:version] if name == 'v'

          # An empty value is an error only for a tag the parser understands;
          # an unknown tag is ignored either way.
          return [:unknown] if value.empty? && !KNOWN_TAGS.include?(name)
          return [:empty] if value.empty?

          if (keywords = KEYWORD_TAGS[name])
            keyword(name, keywords, value)
          elsif (max = DIGIT_TAGS[name])
            digits(name, max, value)
          elsif name == 'fo'
            fo(value)
          elsif URI_TAGS.include?(name)
            uri_list(name, value, segment)
          else
            [:unknown]
          end
        end

        def keyword(name, keywords, value)
          folded = value.downcase(:ascii)

          return [:ok, name.to_sym, folded.to_sym] if keywords.include?(folded)

          # A known keyword followed by junk is a malformed record, not an
          # invalid value: the value grammar matched and the remainder did not.
          malformed!(value) if keywords.any? { |keyword| folded.start_with?(keyword) }

          [:invalid]
        end

        def digits(name, max, value)
          if value.match?(/\A\d+\z/)
            return [:invalid] if value.length > max

            return [:ok, name.to_sym, value.to_i]
          end

          malformed!(value) if value.match?(/\A\d/)

          [:invalid]
        end

        def fo(value)
          folded = value.downcase(:ascii)
          return [:ok, :fo, folded.split(':')] if folded.match?(/\A[01ds](?::[01ds])*\z/)

          malformed!(value) if folded.match?(/\A[01ds](?::[01ds])*/)

          [:invalid]
        end

        def uri_list(name, value, _segment)
          uris = []
          scanner = StringScanner.new(value)

          loop do
            uri = parse_uri(scanner)

            # Any failure inside a URI makes the whole tag invalid.
            return [:invalid] if uri.nil?

            uris << uri

            scanner.skip(WSP)

            break if scanner.eos?

            # A valid URI followed by junk is a malformed record.
            malformed!(value) unless scanner.scan(/,/)

            scanner.skip(WSP)

            # A trailing comma leaves no URI to parse.
            return [:invalid] if scanner.eos?
          end

          [:ok, name.to_sym, uris]
        end

        #
        # Parses one `mailto:` URI, with its optional size and unit.
        #
        # @return [Uri, nil]
        #   The URI, or `nil` when the value is not a valid DMARC URI.
        #
        def parse_uri(scanner)
          start = scanner.pos

          return nil unless scanner.scan(/mailto:/i) && scanner.scan(ADDRESS)

          uri_text = scanner.string.byteslice(start, scanner.pos - start)
          size = unit = nil

          if scanner.scan(/!/)
            digits = scanner.scan(/\d{1,20}/)

            # A bare `!` or more than twenty digits is an invalid value.
            return nil if digits.nil? || scanner.match?(/\d/)

            size = digits.to_i

            # RFC 7489 requires the numeric portion to fit a uint64.
            return nil if size > (2**64) - 1

            unit = scanner.scan(/[kmgt]/i)&.downcase(:ascii)&.to_sym

            # A second `!` is an invalid value.
            return nil if scanner.match?(/!/)
          end

          parsed = begin
            URI.parse(uri_text)
          rescue URI::Error
            return nil
          end

          return nil unless parsed.is_a?(URI::MailTo)

          Uri.new(parsed, size, unit)
        end

        #
        # Raises for input whose valid prefix was followed by junk.
        #
        def malformed!(value)
          raise InvalidRecord, "invalid DMARC record: #{truncate(value).inspect}"
        end

        #
        # Validates parsed tag values that have a range.
        #
        def validate!(tags)
          if tags[:pct] && !tags[:pct].between?(0, 100)
            raise InvalidRecord, 'pct must be an integer between 0 and 100'
          end

          if tags[:ri] && !tags[:ri].between?(0, 2**32 - 1)
            raise InvalidRecord, 'ri must be an integer between 0 and 4294967295'
          end

          tags
        end

        #
        # Truncates an error message to a bounded length.
        #
        def truncate(message)
          message = message.to_s

          if message.length > MAX_ERROR_MESSAGE_LENGTH
            message[0, MAX_ERROR_MESSAGE_LENGTH] + '...'
          else
            message
          end
        end
      end
    end
  end
end
