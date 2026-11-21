# frozen_string_literal: true

require 'ipaddr'
require 'openssl'
require 'socket'

require_relative '../exceptions'
require_relative 'encrypted'

module DMARCator
  module Resolver
    #
    # DNS over TLS transport ([RFC 7858]).
    #
    # The server is configured by the caller; no provider is assumed. When the
    # server is an IP literal, TLS still verifies the certificate against that
    # address, and `sni:` can name a hostname to verify instead.
    #
    # [RFC 7858]: https://www.rfc-editor.org/rfc/rfc7858
    #
    # @since 0.6.0
    #
    class DoT < Encrypted
      # Default DoT port.
      DEFAULT_PORT = 853

      # Default connect/read timeout in seconds.
      DEFAULT_TIMEOUT = 5

      # @return [String] the server host or address.
      attr_reader :host

      # @return [Integer] the server port.
      attr_reader :port

      # @return [String] the name to verify the certificate against.
      attr_reader :sni

      # @return [Integer] connect/read timeout in seconds.
      attr_reader :timeout

      #
      # Builds a resolver from environment variables.
      #
      # @param [Hash] env
      #
      # @return [DoT]
      #
      # @raise [ArgumentError]
      #   `DMARCATOR_DOT_SERVER` is missing or malformed.
      #
      def self.from_env(env = ENV)
        server = env['DMARCATOR_DOT_SERVER']

        if server.nil? || server.empty?
          raise ArgumentError, 'DMARCATOR_DNS=dot requires DMARCATOR_DOT_SERVER (host[:port])'
        end

        host, port = split_server(server)
        sni = env['DMARCATOR_DOT_SNI']

        new(
          host: host,
          port: port,
          sni: sni.nil? || sni.empty? ? nil : sni,
          timeout: timeout_from(env)
        )
      end

      #
      # Splits `host`, `host:port`, `[v6]`, or `[v6]:port`.
      #
      # @param [String] server
      #
      # @return [Array(String, Integer)]
      #
      # @raise [ArgumentError]
      #   The value is malformed.
      #
      def self.split_server(server)
        if (match = /\A\[(?<host>[^\]]+)\](?::(?<port>\d+))?\z/.match(server))
          [match[:host], (match[:port] || DEFAULT_PORT).to_i]
        elsif (match = /\A(?<host>[^:]+)(?::(?<port>\d+))?\z/.match(server))
          [match[:host], (match[:port] || DEFAULT_PORT).to_i]
        else
          raise ArgumentError, "invalid DMARCATOR_DOT_SERVER: #{server.inspect}"
        end
      end

      def self.timeout_from(env)
        value = env['DMARCATOR_DNS_TIMEOUT']

        value.nil? || value.empty? ? DEFAULT_TIMEOUT : Integer(value, 10)
      end

      def initialize(host:, port: DEFAULT_PORT, sni: nil, timeout: DEFAULT_TIMEOUT)
        @host = host
        @port = port
        @sni = sni || host
        @timeout = timeout
      end

      private

      def exchange(query)
        wire = query.encode

        with_tls do |socket|
          socket.write([wire.bytesize].pack('n') + wire)

          header = socket.read(2)

          raise ResolutionError, 'short DoT response' if header.nil? || header.bytesize < 2

          body = socket.read(header.unpack1('n'))
          raise ResolutionError, 'short DoT response' if body.nil?

          body
        end
      rescue ResolutionError
        raise
      rescue StandardError => error
        raise ResolutionError, "DoT request failed: #{error.message}"
      end

      def with_tls
        tcp = Socket.tcp(@host, @port, connect_timeout: @timeout)
        socket = nil

        begin
          tcp.timeout = @timeout if tcp.respond_to?(:timeout=)

          context = OpenSSL::SSL::SSLContext.new
          context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          context.set_params

          socket = OpenSSL::SSL::SSLSocket.new(tcp, context)
          socket.hostname = @sni unless ip_literal?(@sni)
          socket.sync_close = true
          socket.connect
          socket.post_connection_check(@sni)

          yield socket
        ensure
          close_quietly(socket) if socket
          close_quietly(tcp)
        end
      end

      def ip_literal?(value)
        IPAddr.new(value.to_s)

        true
      rescue IPAddr::Error, ArgumentError
        false
      end

      def close_quietly(io)
        io.close
      rescue StandardError
        nil
      end
    end
  end
end
