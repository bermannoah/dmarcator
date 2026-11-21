# frozen_string_literal: true

require 'resolv'
require 'securerandom'

require_relative '../exceptions'

module DMARCator
  module Resolver
    #
    # Base class for encrypted DNS transports (DoH and DoT).
    #
    # Subclasses implement {#exchange}, which sends one encoded DNS query and
    # returns the encoded response. Everything else - query construction,
    # response validation and CNAME following - is shared here.
    #
    # @abstract
    #
    # @since 0.6.0
    #
    # @api private
    #
    class Encrypted
      # Maximum number of CNAME indirections to follow.
      MAX_CNAME_DEPTH = 8

      #
      # Looks up resource records, matching `Resolv::DNS#getresources`.
      #
      # @param [String, Resolv::DNS::Name] name
      #   The name to look up.
      #
      # @param [Class] type
      #   The resource record type, e.g.
      #   `Resolv::DNS::Resource::IN::TXT`.
      #
      # @return [Array<Resolv::DNS::Resource>]
      #
      # @raise [ResolutionError]
      #   The transport failed or returned an unusable response.
      #
      def getresources(name, type)
        fetch(dns_name(name), type, MAX_CNAME_DEPTH)
      end

      private

      def dns_name(name)
        return name if name.is_a?(Resolv::DNS::Name)

        Resolv::DNS::Name.create(name.to_s)
      end

      def fetch(name, type, depth)
        # A predictable transaction ID would let an off-path attacker guess the
        # query before it is answered. Over TLS this is already unreachable, but
        # the plaintext TCP transport shares this code path.
        id = SecureRandom.random_number(0x10000)
        message = decode_response(exchange(build_query(id, name, type)), id, name, type)

        case message.rcode
        when Resolv::DNS::RCode::NoError
          collect(message, name, type, depth)
        when Resolv::DNS::RCode::NXDomain
          []
        else
          raise ResolutionError, "DNS query failed with rcode #{message.rcode}"
        end
      end

      def collect(message, name, type, depth)
        # Only answers owned by the queried name are usable: a response may
        # carry records for other owners (an injected CNAME chain, or a
        # malicious answer), and accepting them would let the transport return
        # a record for a different name.
        matching = message.answer.select do |owner, _ttl, record|
          record.is_a?(type) && same_name?(owner, name)
        end
        return matching.map { |_name, _ttl, record| record } unless matching.empty?

        cname = message.answer.find do |owner, _ttl, record|
          record.is_a?(Resolv::DNS::Resource::IN::CNAME) && same_name?(owner, name)
        end

        return fetch(cname[2].name, type, depth - 1) if cname && depth.positive?

        []
      end

      def build_query(id, name, type)
        message = Resolv::DNS::Message.new(id)
        message.rd = 1
        message.add_question(name, type)
        message
      end

      def decode_response(wire, id, name, type)
        raise ResolutionError, 'empty DNS response' if wire.nil? || wire.empty?

        message = begin
          Resolv::DNS::Message.decode(wire)
        rescue StandardError => error
          raise ResolutionError, "malformed DNS response: #{error.message}"
        end

        unless message.id == id
          raise ResolutionError, 'unexpected DNS response (transaction mismatch)'
        end

        # `Message.decode` returns early for truncated responses, leaving the
        # remaining header fields unset, so check the TC bit first.
        raise ResolutionError, 'truncated DNS response' unless message.tc.to_i.zero?

        unless message.qr == 1
          raise ResolutionError, 'unexpected DNS response (not a response)'
        end

        question = message.question.first

        unless question && same_name?(question[0], name) && question[1] == type
          raise ResolutionError, 'unexpected DNS response (question mismatch)'
        end

        message
      end

      #
      # Compares DNS names case-insensitively and ignoring a trailing root dot.
      # `Resolv::DNS::Name#==` treats `example.com` and `example.com.` as
      # different, but a decoded response always carries the absolute form.
      #
      def same_name?(left, right)
        normalize_name(left) == normalize_name(right)
      end

      def normalize_name(value)
        value.to_s.downcase.chomp('.')
      end
    end
  end
end
