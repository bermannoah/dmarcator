# frozen_string_literal: true

module DMARCator
  #
  # Process-wide defaults.
  #
  # @since 0.11.0
  #
  class Config
    # Default maximum accepted report size in bytes (25 MiB).
    #
    # Parsing a report builds a DOM roughly 13x the input size, so this bounds
    # the memory a hostile report can cost.
    #
    # @since 0.12.0
    #
    DEFAULT_MAX_REPORT_BYTES = 25 * 1024 * 1024

    # Default maximum number of `record` elements accepted in a report.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_REPORT_RECORDS = 10_000

    # Default maximum number of XML nodes accepted in a report.
    #
    # Counts element, text, CDATA, whitespace, comment and processing
    # instruction nodes; attributes are counted separately by
    # {DEFAULT_MAX_XML_ATTRIBUTES}.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_XML_NODES = 100_000

    # Default maximum element nesting depth accepted in a report.
    #
    # The root element is depth 1.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_XML_DEPTH = 50

    # Default maximum length in bytes of any single text node.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_TEXT_LENGTH = 1 * 1024 * 1024

    # Default maximum number of attribute nodes accepted in a report.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_XML_ATTRIBUTES = 100_000

    # Default maximum number of `auth_results` entries per record.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_AUTH_RESULTS = 100

    # Default maximum number of `reason` entries per record.
    #
    # @since 1.3.0
    #
    DEFAULT_MAX_REASONS = 100

    #
    # The default resolver used when a lookup is not given one.
    #
    # Either a resolver ({Resolv::DNS}, {Resolver::DoH}, {Resolver::DoT}) or a
    # callable returning one. Prefer a callable in threaded applications: a
    # resolver object is shared by every thread, and `Resolv::DNS` does not
    # serialise concurrent lookups.
    #
    # @return [Object, #call, nil]
    #
    attr_accessor :resolver

    #
    # The maximum accepted report size in bytes.
    #
    # Defaults to {DEFAULT_MAX_REPORT_BYTES}. Lower it to bound memory for
    # reports from untrusted sources.
    #
    # @return [Integer]
    #
    def max_report_bytes
      @max_report_bytes || DEFAULT_MAX_REPORT_BYTES
    end

    #
    # Sets the maximum accepted report size in bytes.
    #
    # @param [Integer, nil] value
    #   A positive number of bytes, or `nil` to restore the default.
    #
    # @raise [ArgumentError]
    #   The value is not a positive Integer or nil.
    #
    def max_report_bytes=(value)
      unless value.nil? || (value.is_a?(Integer) && value.positive?)
        raise ArgumentError,
              "max_report_bytes must be a positive Integer or nil, got #{value.inspect}"
      end

      @max_report_bytes = value
    end

    #
    # XML report complexity limits.
    #
    # Each accepts a positive Integer or `nil` (to restore the default). A
    # report that exceeds one of these raises {ReportTooComplex} when parsed.
    # They bound parser work on hostile input; see {DMARCator::Report}.
    #
    # @!method max_report_records
    #   @return [Integer] the maximum number of `record` elements.
    # @!method max_report_records=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    # @!method max_xml_nodes
    #   @return [Integer] the maximum number of XML nodes.
    # @!method max_xml_nodes=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    # @!method max_xml_depth
    #   @return [Integer] the maximum element nesting depth (root is 1).
    # @!method max_xml_depth=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    # @!method max_text_length
    #   @return [Integer] the maximum text node length in bytes.
    # @!method max_text_length=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    # @!method max_xml_attributes
    #   @return [Integer] the maximum number of attribute nodes.
    # @!method max_xml_attributes=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    # @!method max_auth_results
    #   @return [Integer] the maximum number of `auth_results` entries per record.
    # @!method max_auth_results=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    # @!method max_reasons
    #   @return [Integer] the maximum number of `reason` entries per record.
    # @!method max_reasons=(value)
    #   @param [Integer, nil] value
    #   @raise [ArgumentError] the value is not a positive Integer or nil.
    #
    {
      max_report_records: DEFAULT_MAX_REPORT_RECORDS,
      max_xml_nodes: DEFAULT_MAX_XML_NODES,
      max_xml_depth: DEFAULT_MAX_XML_DEPTH,
      max_text_length: DEFAULT_MAX_TEXT_LENGTH,
      max_xml_attributes: DEFAULT_MAX_XML_ATTRIBUTES,
      max_auth_results: DEFAULT_MAX_AUTH_RESULTS,
      max_reasons: DEFAULT_MAX_REASONS
    }.each do |name, default|
      define_method(name) do
        instance_variable_get(:"@#{name}") || default
      end

      define_method(:"#{name}=") do |value|
        unless value.nil? || (value.is_a?(Integer) && value.positive?)
          raise ArgumentError,
                "#{name} must be a positive Integer or nil, got #{value.inspect}"
        end

        instance_variable_set(:"@#{name}", value)
      end
    end
  end

  #
  # The process-wide configuration.
  #
  # @return [Config]
  #
  # @since 0.11.0
  #
  def self.config
    @config ||= Config.new
  end

  #
  # Configures process-wide defaults.
  #
  #   DMARCator.configure do |config|
  #     config.resolver = -> { Resolv::DNS.new }
  #   end
  #
  # When set, a configured resolver takes precedence over `DMARCATOR_DNS` and
  # is used by {txt}, {txt_records}, {dmarc} and {Record.lookup} whenever no
  # resolver is passed explicitly.
  #
  # @yieldparam [Config] config
  #
  # @return [Config]
  #
  # @since 0.11.0
  #
  def self.configure
    yield config if block_given?
    config
  end

  #
  # Discards any configured defaults.
  #
  # @return [Config]
  #
  # @since 0.11.0
  #
  def self.reset_configuration!
    @config = Config.new
  end
end
