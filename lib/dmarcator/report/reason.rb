# frozen_string_literal: true

require_relative '../internal/xml_helper'

module DMARCator
  class Report
    #
    # Represents a `reason` element of a DMARC XML report record.
    #
    class Reason
      include Internal::XmlHelper

      # Attribute names exposed by this class.
      ATTRIBUTES = %i[type comment].freeze

      # @!attribute [r] type
      #   @return [String, nil] the reason type.
      # @!attribute [r] comment
      #   @return [String, nil] an optional explanatory comment.
      ATTRIBUTES.each { |attribute| attr_reader(attribute) }

      def initialize(node)
        @node = node

        node.element_children.each do |element|
          case element.name
          when 'type'
            @type ||= element.text.freeze
          when 'comment'
            @comment ||= element.text.freeze
          end
        end
      end
    end
  end
end
