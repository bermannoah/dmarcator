# frozen_string_literal: true

require 'net/http'
require 'openssl'
require 'uri'

require_relative '../exceptions'
require_relative 'encrypted'

module DMARCator
  module Resolver
    #
    # DNS over HTTPS transport ([RFC 8484]).
    #
    # The endpoint is configured by the caller; no provider is assumed. To avoid
    # needing DNS to reach the DNS server, pass `ipaddr:` (or set
    # `DMARCATOR_DOH_IP`) to pin the connection while TLS still verifies the
    # certificate against the URL's hostname.
    #
    # [RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484
    #
    # @since 0.6.0
    #
    class DoH < Encrypted
      # Default connect/read timeout in seconds.
      DEFAULT_TIMEOUT = 5

      # Maximum accepted response body in bytes (the DNS message limit).
      MAX_RESPONSE_BYTES = 65_535

      # Media type RFC 8484 requires for DNS messages.
      CONTENT_TYPE = 'application/dns-message'

      # @return [URI::HTTPS] the DoH endpoint.
      attr_reader :url

      # @return [String, nil] the address to connect to instead of resolving
      #   the endpoint hostname.
      attr_reader :ipaddr

      # @return [Integer] connect/read timeout in seconds.
      attr_reader :timeout

      #
      # Builds a resolver from environment variables.
      #
      # @param [Hash] env
      #
      # @return [DoH]
      #
      # @raise [ArgumentError]
      #   `DMARCATOR_DOH_URL` is missing or not an HTTPS URL, or
      #   `DMARCATOR_DNS_TIMEOUT` is not a positive integer.
      #
      def self.from_env(env = ENV)
        url = env['DMARCATOR_DOH_URL']

        if url.nil? || url.empty?
          raise ArgumentError, 'DMARCATOR_DNS=doh requires DMARCATOR_DOH_URL'
        end

        new(
          url: url,
          ipaddr: presence(env['DMARCATOR_DOH_IP']),
          timeout: timeout_from(env)
        )
      end

      def self.presence(value)
        value unless value.nil? || value.empty?
      end

      def self.timeout_from(env)
        super(env, DEFAULT_TIMEOUT)
      end

      def initialize(url:, ipaddr: nil, timeout: DEFAULT_TIMEOUT)
        @url = URI.parse(url)

        unless @url.is_a?(URI::HTTPS) && @url.host
          raise ArgumentError, "DoH endpoint must be an https URL: #{url.inspect}"
        end

        @ipaddr = ipaddr
        @timeout = timeout
      end

      private

      def exchange(query)
        http = Net::HTTP.new(@url.host, @url.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = @timeout
        http.read_timeout = @timeout
        http.write_timeout = @timeout
        http.ipaddr = @ipaddr if @ipaddr

        request = Net::HTTP::Post.new(@url.request_uri)
        request['content-type'] = CONTENT_TYPE
        request['accept'] = CONTENT_TYPE
        request.body = query.encode

        body = +''.b

        http.start do |connection|
          connection.request(request) do |response|
            status = response.code.to_i

            unless status.between?(200, 299)
              raise ResolutionError, "DoH endpoint returned HTTP #{status}"
            end

            content_type = response['content-type'].to_s

            unless content_type.start_with?(CONTENT_TYPE)
              raise ResolutionError,
                    "DoH endpoint returned unexpected content-type: #{content_type.inspect}"
            end

            # Reject a declared oversize before reading anything, then enforce
            # the same bound while streaming, so a chunked or lying response
            # cannot allocate more than the limit.
            if response['content-length'].to_i > MAX_RESPONSE_BYTES
              raise ResolutionError,
                    "DoH response exceeds maximum size of #{MAX_RESPONSE_BYTES} bytes"
            end

            response.read_body do |chunk|
              body << chunk.b

              if body.bytesize > MAX_RESPONSE_BYTES
                raise ResolutionError,
                      "DoH response exceeds maximum size of #{MAX_RESPONSE_BYTES} bytes"
              end
            end
          end
        end

        body
      rescue ResolutionError
        raise
      rescue StandardError => error
        raise ResolutionError, "DoH request failed: #{error.message}"
      end
    end
  end
end
