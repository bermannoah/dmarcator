# frozen_string_literal: true

require 'resolv'
require 'socket'

require_relative '../exceptions'
require_relative 'encrypted'

module DMARCator
  module Resolver
    #
    # Plain DNS over TCP ([RFC 1035] section 4.2.2).
    #
    # TCP rather than UDP on purpose. `Resolv::DNS` reads UDP replies into a
    # 512-byte buffer, so a larger answer cannot be decoded, is discarded, and
    # the resulting timeout is swallowed unless `raise_timeout_errors` is set.
    # Large TXT sets - SPF records, several DKIM keys - therefore came back as
    # an empty result, which looks exactly like "no records published". TCP has
    # no such limit, and failures here raise {ResolutionError}.
    #
    # [RFC 1035]: https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2
    #
    # @since 1.2.0
    #
    class Plain < Encrypted
      # Default DNS port.
      DEFAULT_PORT = 53

      # Default connect/read timeout in seconds.
      DEFAULT_TIMEOUT = 5

      # @return [Array<Array(String, Integer)>] the nameservers to try.
      attr_reader :nameservers

      # @return [Integer] connect/read timeout in seconds.
      attr_reader :timeout

      #
      # Builds a resolver from environment variables.
      #
      # @param [Hash] env
      #
      # @return [Plain]
      #
      # @raise [ArgumentError]
      #   `DMARCATOR_DNS_TIMEOUT` is not a positive integer.
      #
      def self.from_env(env = ENV)
        new(timeout: timeout_from(env))
      end

      def self.timeout_from(env)
        super(env, DEFAULT_TIMEOUT)
      end

      #
      # The nameservers from the system resolver configuration.
      #
      # @return [Array<Array(String, Integer)>]
      #
      def self.system_nameservers
        config = Resolv::DNS::Config.default_config_hash

        if (ports = config[:nameserver_port]) && !ports.empty?
          return ports.map { |host, port| [host, port || DEFAULT_PORT] }
        end

        servers = Array(config[:nameserver])
        servers = ['127.0.0.1'] if servers.empty?

        servers.map { |host| [host, DEFAULT_PORT] }
      end

      def initialize(nameservers: nil, timeout: DEFAULT_TIMEOUT)
        @nameservers = (nameservers || self.class.system_nameservers).freeze
        @timeout = timeout

        raise ArgumentError, 'no nameservers configured' if @nameservers.empty?
      end

      private

      def exchange(query)
        wire = query.encode
        last_error = nil

        @nameservers.each do |host, port|
          begin
            return request(host, port, wire)
          rescue ResolutionError, SystemCallError, SocketError, IOError => error
            # Try the remaining nameservers, but do not swallow an error that
            # indicates a bug in the transport.
            last_error = error
          end
        end

        raise ResolutionError,
              "DNS lookup failed: #{last_error&.message || 'no nameservers'}"
      end

      def request(host, port, wire)
        socket = Socket.tcp(host, port, connect_timeout: @timeout)
        socket.timeout = @timeout if socket.respond_to?(:timeout=)

        socket.write([wire.bytesize].pack('n') + wire)

        header = socket.read(2)
        raise ResolutionError, 'short DNS response' if header.nil? || header.bytesize < 2

        length = header.unpack1('n')
        body = socket.read(length)

        if body.nil? || body.bytesize != length
          raise ResolutionError,
                "short DNS response (expected #{length} bytes, got #{body&.bytesize || 0})"
        end

        body
      ensure
        socket&.close
      end
    end
  end
end
