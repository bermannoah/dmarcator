# frozen_string_literal: true

require 'dmarcator/query'
require 'dmarcator/internal/parser'
require 'dmarcator/exceptions'

require 'resolv'

module DMARCator
  #
  # A parsed DMARC record, as published in a `_dmarc.<domain>` TXT record.
  #
  # @see https://www.rfc-editor.org/rfc/rfc7489
  #
  class Record

    # `p` field.
    #
    # @return [:none, :quarantine, :reject]
    attr_reader :p

    # `rua` field.
    #
    # @return [Array<Uri>]
    attr_reader :rua

    # `ruf` field.
    #
    # @return [Array<Uri>]
    attr_reader :ruf

    # `v` field.
    #
    # @return [:DMARC1]
    attr_reader :v

    # Default value of the `fo=` field.
    DEFAULT_FO = %w[0].freeze
    private_constant :DEFAULT_FO

    #
    # Initializes the record.
    #
    # @param [Hash{Symbol => Object}] attributes
    #   Attributes for the record.
    #
    # @option attributes [:r, :s] :adkim (:r)
    #
    # @option attributes [:r, :s] :aspf (:r)
    #
    # @option attributes [Array<String>] :fo (['0'])
    #
    # @option attributes [:none, :quarantine, :reject] :p
    #
    # @option attributes [Integer] :pct (100)
    #
    # @option attributes [:afrf, :iodef] :rf (:afrf)
    #
    # @option attributes [Integer] :ri (86400)
    #
    # @option attributes [Array<Uri>] :rua
    #
    # @option attributes [Array<Uri>] :ruf
    #
    # @option attributes [:none, :quarantine, :reject] :sp
    #
    # @option attributes [:DMARC1] :v
    #
    def initialize(attributes={})
      @v     = attributes.fetch(:v)
      @adkim = attributes[:adkim]
      @aspf  = attributes[:aspf]
      @fo    = attributes[:fo]&.map(&:freeze)&.freeze
      @p     = attributes[:p]
      @pct   = attributes[:pct]
      @rf    = attributes[:rf]
      @ri    = attributes[:ri]
      @rua   = attributes[:rua]&.freeze
      @ruf   = attributes[:ruf]&.freeze
      @sp    = attributes[:sp]
    end

    #
    # Determines if the `sp=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def sp?
      !@sp.nil?
    end

    #
    # The `sp=` field.
    #
    # @return [:none, :quarantine, :reject]
    #   The value of the `sp=` field, or that of {#p} if the field was omitted.
    #
    def sp
      @sp || @p
    end

    #
    # Determines whether the `adkim=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def adkim?
      !@adkim.nil?
    end

    #
    # `adkim=` field.
    #
    # @return [:r, :s]
    #   The value of the `adkim=` field, or `:r` if the field was omitted.
    #
    def adkim
      @adkim || :r
    end

    #
    # Determines whether the `aspf=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def aspf?
      !@aspf.nil?
    end

    #
    # `aspf` field.
    #
    # @return [:r, :s]
    #   The value of the `aspf=` field, or `:r` if the field was omitted.
    #
    def aspf
      @aspf || :r
    end

    #
    # Determines whether the `fo=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def fo?
      !@fo.nil?
    end

    #
    # `fo` field.
    #
    # @return [Array<String>]
    #   The value of the `fo=` field, or `["0"]` if the field was omitted.
    #
    def fo
      @fo || DEFAULT_FO
    end

    #
    # Determines if the `p=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def p?
      !@p.nil?
    end

    #
    # Determines whether the `pct=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def pct?
      !@pct.nil?
    end

    #
    # `pct` field.
    #
    # @return [Integer]
    #   The value of the `pct=` field, or `100` if the field was omitted.
    #
    def pct
      @pct || 100
    end

    #
    # Determines whether the `rf=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def rf?
      !@rf.nil?
    end

    #
    # `rf` field.
    # 
    # @return [:afrf, :iodef]
    #   The value of the `rf=` field, or `:afrf` if the field was omitted.
    #
    def rf
      @rf || :afrf
    end

    #
    # Determines whether the `ri=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def ri?
      !@ri.nil?
    end

    #
    # `ri` field.
    #
    # @return [Integer]
    #   The value of the `ri=` field, or `86400` if the field was omitted.
    #
    def ri
      @ri || 86400
    end

    #
    # Determines if the `rua=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def rua?
      !@rua.nil?
    end

    #
    # Determines if the `ruf=` field was specified.
    #
    # @return [Boolean]
    #
    # @since 0.4.0
    #
    def ruf?
      !@ruf.nil?
    end

    #
    # Parses a DMARC record.
    #
    # @param [String] record
    #   The raw DMARC record.
    #
    # @param [Boolean] strict (false)
    #   When `true`, raise on unknown tags or invalid tag values instead of
    #   silently ignoring them.
    #
    # @return [Record]
    #   The parsed DMARC record.
    #
    # @raise [InvalidRecord]
    #   The DMARC record could not be parsed.
    #
    # @since 0.3.0
    #
    # @api public
    #
    def self.parse(record, strict: false)
      attributes = Internal::Parser.parse(record, strict: strict)

      unless attributes[:p]
        raise InvalidRecord, "DMARC record is missing the required 'p' tag"
      end

      new(attributes)
    end

    #
    # Looks up and parses the DMARC record for a domain.
    #
    # Prefer {DMARCator.dmarc} for bulk work: this method adds a parse
    # (roughly 0.4 ms) on top of the lookup.
    #
    # @param [String] domain
    #   The domain to look up DMARC for.
    #
    # @param [Resolv::DNS, DMARCator::Resolver::DoH, DMARCator::Resolver::DoT] resolver
    #   The resolver to use. When omitted, one is built from `DMARCATOR_DNS`.
    #
    # @return [Record, nil]
    #   The parsed DMARC record, or `nil` when the domain publishes none.
    #
    # @raise [InvalidRecord]
    #   The DMARC record could not be parsed.
    #
    # @raise [DMARCator::ResolutionError]
    #   The lookup failed.
    #
    # @since 0.8.0
    #
    # @api public
    #
    def self.lookup(domain, resolver: DMARCator.default_resolver)
      if (dmarc = DMARCator.dmarc(domain, resolver: resolver))
        parse(dmarc)
      end
    end

    #
    # Converts the record to a Hash.
    #
    # @return [Hash{Symbol => Object}]
    #
    # @since 0.4.0
    #
    def to_h
      hash = {}

      hash[:v]     = @v     if @v
      hash[:p]     = @p     if @p
      hash[:sp]    = @sp    if @sp
      hash[:rua]   = @rua   if @rua
      hash[:ruf]   = @ruf   if @ruf
      hash[:adkim] = @adkim if @adkim
      hash[:aspf]  = @aspf  if @aspf
      hash[:ri]    = @ri    if @ri
      hash[:fo]    = @fo    if @fo
      hash[:rf]    = @rf    if @rf
      hash[:pct]   = @pct   if @pct

      return hash
    end

    #
    # Converts the record back to a DMARC String.
    #
    # @return [String]
    #
    def to_s
      tags = []

      tags << "v=#{@v}"               if @v
      tags << "p=#{@p}"               if @p
      tags << "sp=#{@sp}"             if @sp
      tags << "rua=#{@rua.map(&:to_s).join(',')}" if @rua
      tags << "ruf=#{@ruf.map(&:to_s).join(',')}" if @ruf
      tags << "adkim=#{@adkim}"       if @adkim
      tags << "aspf=#{@aspf}"         if @aspf
      tags << "ri=#{@ri}"             if @ri
      tags << "fo=#{@fo.join(':')}"   if @fo
      tags << "rf=#{@rf}"             if @rf
      tags << "pct=#{@pct}"           if @pct

      return tags.join('; ')
    end

  end
end
