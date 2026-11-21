# frozen_string_literal: true

require_relative '../internal/xml_helper'

module DMARCator
  class Report
    #
    # Represents the `report_metadata` element of a DMARC XML report.
    #
    class Metadata
      include Internal::XmlHelper

      # Attribute names exposed by this class.
      ATTRIBUTES = %i[
        org_name email extra_contact_info report_id
        begin_at end_at errors
      ].freeze

      # @!attribute [r] org_name
      #   @return [String, nil] the reporting organization.
      # @!attribute [r] email
      #   @return [String, nil] the reporting organization's contact address.
      # @!attribute [r] extra_contact_info
      #   @return [String, nil] additional contact information.
      # @!attribute [r] report_id
      #   @return [String, nil] the unique report identifier.
      # @!attribute [r] begin_at
      #   @return [Time, nil] the start of the reporting interval.
      # @!attribute [r] end_at
      #   @return [Time, nil] the end of the reporting interval.
      # @!attribute [r] errors
      #   @return [Array<String>] errors reported by the reporting organization.
      ATTRIBUTES.each { |attribute| attr_reader(attribute) }

      def initialize(node)
        @node = node
        @errors = []

        metadata = node.at_xpath('feedback/report_metadata')

        # `report_metadata` is required by the DMARC schema, but the XML guard
        # only enforces the `<feedback>` root, so an attacker-supplied report can
        # omit it. Treat it like a missing `policy_published` rather than
        # raising NoMethodError out of a public accessor.
        return unless metadata

        metadata.element_children.each do |element|
          case element.name
          when 'org_name'
            @org_name ||= element.text.freeze
          when 'email'
            @email ||= element.text.freeze
          when 'extra_contact_info'
            @extra_contact_info ||= element.text.freeze
          when 'report_id'
            @report_id ||= element.text.freeze
          when 'error'
            errors << element.text.freeze
          when 'date_range'
            parse_date_range(element)
          end
        end
      ensure
        @errors.freeze
      end

      private

      def parse_date_range(date_range)
        date_range.element_children.each do |element|
          case element.name
          when 'begin'
            @begin_at ||= parse_timestamp(element.text.freeze)
          when 'end'
            @end_at ||= parse_timestamp(element.text.freeze)
          end
        end
      end
    end
  end
end
