# frozen_string_literal: true

require_relative '../internal/xml_helper'

module DMARCator
  class Report
    #
    # Represents the `policy_published` element of a DMARC XML report.
    #
    class Policy
      include Internal::XmlHelper

      # Attribute names exposed by this class.
      ATTRIBUTES = %i[domain adkim aspf p sp pct fo].freeze

      # @!attribute [r] domain
      #   @return [String, nil] the domain the policy applies to.
      # @!attribute [r] adkim
      #   @return [String, nil] the DKIM alignment mode (`r` or `s`).
      # @!attribute [r] aspf
      #   @return [String, nil] the SPF alignment mode (`r` or `s`).
      # @!attribute [r] p
      #   @return [String, nil] the requested policy.
      # @!attribute [r] sp
      #   @return [String, nil] the requested subdomain policy.
      # @!attribute [r] pct
      #   @return [Integer, nil] the percentage of messages the policy applied to.
      # @!attribute [r] fo
      #   @return [String, nil] the requested failure-reporting options.
      ATTRIBUTES.each { |attribute| attr_reader(attribute) }

      def initialize(node)
        @node = node

        policy = node.at_xpath('feedback/policy_published')
        return unless policy

        policy.element_children.each do |element|
          case element.name
          when 'pct'
            @pct ||= parse_integer(element.text.freeze)
          when 'domain'
            @domain ||= element.text.freeze
          when 'adkim'
            @adkim ||= element.text.freeze
          when 'aspf'
            @aspf ||= element.text.freeze
          when 'p'
            @p ||= element.text.freeze
          when 'sp'
            @sp ||= element.text.freeze
          when 'fo'
            @fo ||= element.text.freeze
          end
        end
      end
    end
  end
end
