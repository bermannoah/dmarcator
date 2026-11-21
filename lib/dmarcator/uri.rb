# frozen_string_literal: true

module DMARCator
  #
  # Represents a DMARC URI.
  #
  # @see https://tools.ietf.org/html/rfc7489#section-6.2
  #
  # @since 0.5.0
  #
  class Uri

    # The `mailto:` URI.
    #
    # @return [URI::MailTo]
    attr_reader :uri

    # The optional maximum-size.
    #
    # @return [Integer, nil]
    attr_reader :size

    # The optional unit.
    #
    # @return [:k, :m, :g, :t, nil]
    attr_reader :unit

    #
    # Initializes the DMARC URI.
    #
    # @param [URI::MailTo] uri
    #   The `mailto:` URI.
    #
    # @param [Integer] size
    #   The optional maximum-size.
    #
    # @param [:k, :m, :g, :t] unit
    #   The optional size unit.
    #
    def initialize(uri,size=nil,unit=nil)
      @uri = uri

      @size = size
      @unit = unit
    end

    #
    # Determines if a maximum-size was set.
    #
    # @return [Boolean]
    #
    def size?
      !@size.nil?
    end

    #
    # Determines if a size unit was set.
    #
    # @return [Boolean]
    #
    def unit?
      !@unit.nil?
    end

    #
    # Determines if the DMARC URI matches the other.
    #
    # @param [Object] other
    #   the other DMARC URI to compare against.
    #
    # @return [Boolean]
    #
    def ==(other)
      (self.class == other.class) &&
      (@uri == other.uri) &&
      (@size == other.size) &&
      (@unit == other.unit)
    end

    #
    # Determines if the DMARC URI is equivalent to the other.
    #
    # @param [Object] other
    #   the other DMARC URI to compare against.
    #
    # @return [Boolean]
    #
    def eql?(other)
      self == other
    end

    #
    # Computes a hash value consistent with {#eql?}.
    #
    # @return [Integer]
    #
    def hash
      [self.class, @uri, @size, @unit].hash
    end

    #
    # Converts the DMARC URI back into a String.
    #
    # @return [String]
    #
    def to_s
      str = @uri.to_s

      if (@size || @unit)
        str << "!"
        str << "#{@size}" if @size
        str << "#{@unit}" if @unit
      end

      return str
    end

    #
    # Converts the DMARC URI into a String.
    #
    # Same as {#to_s}. It is defined so implicit String conversion, such as
    # `Array#join` or `String#+`, keeps the optional size and unit instead of
    # falling through to the wrapped URI.
    #
    # @return [String]
    #
    # @since 1.6.1
    #
    def to_str
      to_s
    end

    private

    #
    # Pass public methods through to {#uri}.
    #
    # Private methods are not forwarded: delegation is limited to the wrapped
    # URI's public interface.
    #
    def method_missing(name,*arguments,&block)
      return super unless @uri.respond_to?(name)

      @uri.public_send(name,*arguments,&block)
    end

    #
    # Indicates whether a missing public method can be handled by {#uri}.
    #
    # @return [Boolean]
    #
    def respond_to_missing?(name, include_private = false)
      @uri.respond_to?(name) || super
    end

  end
end
