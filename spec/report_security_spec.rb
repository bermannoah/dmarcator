# frozen_string_literal: true

require 'spec_helper'
require 'dmarcator/report'

#
# Regression tests for the XML hardening of DMARCator::Report. Report XML is
# untrusted: DTDs and entity declarations are rejected, entity/network
# resolution is disabled, and structural complexity is bounded.
#
RSpec.describe 'DMARC XML report hardening' do
  after { DMARCator.reset_configuration! }

  def nested_xml(depth)
    '<feedback>' + ('<a>' * depth) + 'x' + ('</a>' * depth) + '</feedback>'
  end

  def records_xml(count)
    rows = (1..count).map do |i|
      "<record><row><source_ip>192.0.2.#{i}</source_ip></row></record>"
    end.join

    "<feedback>#{rows}</feedback>"
  end

  describe 'DTD and entity declarations' do
    it 'rejects an external entity (XXE) declaration' do
      xml = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
        <feedback><report_metadata><org_name>&xxe;</org_name></report_metadata></feedback>
      XML

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ForbiddenXml)
    end

    it 'rejects a standalone DOCTYPE' do
      xml = '<!DOCTYPE feedback><feedback><version>0.1</version></feedback>'

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ForbiddenXml)
    end

    it 'rejects an entity declaration regardless of case' do
      xml = '<!DOCTYPE feedback [<!Entity e "x">]><feedback>&e;</feedback>'

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ForbiddenXml)
    end

    it 'rejects billion-laughs entity expansion at the declaration' do
      entities = (1..9).map do |i|
        "<!ENTITY lol#{i} \"#{(['&lol' + (i - 1).to_s + ';'] * 10).join}\">"
      end.join

      xml = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE lolz [<!ENTITY lol0 "lol">#{entities}]>
        <feedback><report_metadata><org_name>&lol9;</org_name></report_metadata></feedback>
      XML

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ForbiddenXml)
    end

    it 'rejects recursive entity references' do
      xml = <<~XML
        <!DOCTYPE feedback [<!ENTITY a "&b;"><!ENTITY b "&a;">]>
        <feedback><report_metadata><org_name>&a;</org_name></report_metadata></feedback>
      XML

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ForbiddenXml)
    end

    it 'rejects a DTD declared in a UTF-16 encoded report' do
      text = '<?xml version="1.0" encoding="UTF-16"?>' \
             '<!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>' \
             '<feedback><org_name>&xxe;</org_name></feedback>'

      xml = "\xFF\xFE".b + text.encode('UTF-16LE').b

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ForbiddenXml)
    end

    it 'still allows predefined entities and character references' do
      xml = '<feedback><report_metadata><org_name>A&amp;B &#65;</org_name></report_metadata></feedback>'

      expect(DMARCator::Report.new(xml).metadata.org_name).to eq('A&B A')
    end
  end

  describe 'structural limits' do
    it 'rejects reports with excessive records' do
      DMARCator.configure { |c| c.max_report_records = 2 }

      expect {
        DMARCator::Report.new(records_xml(3))
      }.to raise_error(DMARCator::ReportTooComplex, /max_report_records/)
    end

    it 'rejects reports with excessive XML nodes' do
      DMARCator.configure { |c| c.max_xml_nodes = 5 }

      xml = '<feedback><a><b><c><d><e>text</e></d></c></b></a></feedback>'

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ReportTooComplex, /max_xml_nodes/)
    end

    it 'rejects deeply nested XML' do
      expect { DMARCator::Report.new(nested_xml(60)) }
        .to raise_error(DMARCator::ReportTooComplex, /max_xml_depth/)
    end

    it 'accepts nesting within the configured depth' do
      report = DMARCator::Report.new(nested_xml(40))

      expect(report.records).to eq([])
    end

    it 'rejects oversized text nodes' do
      DMARCator.configure { |c| c.max_text_length = 10 }

      xml = '<feedback><report_metadata><org_name>this is far too long</org_name></report_metadata></feedback>'

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ReportTooComplex, /max_text_length/)
    end

    it 'rejects huge text fields inside records' do
      DMARCator.configure { |c| c.max_text_length = 10 }

      xml = "<feedback><record><row><source_ip>#{'a' * 1000}</source_ip></row></record></feedback>"

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ReportTooComplex, /max_text_length/)
    end

    it 'rejects excessive attributes' do
      DMARCator.configure { |c| c.max_xml_attributes = 1 }

      xml = '<feedback a="1" b="2"><version>0.1</version></feedback>'

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::ReportTooComplex, /max_xml_attributes/)
    end

    it 'rejects excessive auth_results entries per record' do
      DMARCator.configure { |c| c.max_auth_results = 1 }

      xml = <<~XML
        <feedback><record>
          <auth_results>
            <dkim><domain>a.example</domain></dkim>
            <spf><domain>b.example</domain></spf>
          </auth_results>
        </record></feedback>
      XML

      expect { DMARCator::Report.new(xml) }
        .to raise_error(DMARCator::ReportTooComplex, /max_auth_results/)
    end

    it 'rejects excessive reason entries per record' do
      DMARCator.configure { |c| c.max_reasons = 1 }

      xml = <<~XML
        <feedback><record><row><policy_evaluated>
          <reason><type>one</type></reason>
          <reason><type>two</type></reason>
        </policy_evaluated></row></record></feedback>
      XML

      expect { DMARCator::Report.new(xml) }
        .to raise_error(DMARCator::ReportTooComplex, /max_reasons/)
    end

    it 'accepts reports within all limits' do
      DMARCator.configure do |c|
        c.max_report_records = 10
        c.max_xml_nodes = 100
        c.max_xml_depth = 20
        c.max_text_length = 100
      end

      report = DMARCator::Report.new(records_xml(2))

      expect(report.records.length).to eq(2)
    end
  end

  describe 'malformed encodings' do
    it 'rejects invalid UTF-8' do
      xml = "<feedback>\xFF\xFE</feedback>".b

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::InvalidReport)
    end

    it 'rejects truncated UTF-16' do
      xml = "\xFF\xFE<\x00f\x00".b

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::InvalidReport)
    end

    it 'rejects a UTF-16 report with an invalid surrogate' do
      # UTF-16LE BOM followed by a tag containing a lone high surrogate
      # (U+D800), which is not valid UTF-16.
      xml = "\xFF\xFE".b + "\x3C\x00\x66\x00\x00\xD8\x2F\x00\x66\x00\x3E\x00".b

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::InvalidReport)
    end

    it 'rejects bytes whose declared encoding does not match' do
      xml = '<?xml version="1.0" encoding="UTF-16"?><feedback><a>x</a></feedback>'

      expect { DMARCator::Report.new(xml) }.to raise_error(DMARCator::InvalidReport)
    end
  end

  describe 'failure classes' do
    it 'are all rescuable as DMARCator::Error' do
      expect(DMARCator::ForbiddenXml.ancestors).to include(DMARCator::Error)
      expect(DMARCator::ReportTooComplex.ancestors).to include(DMARCator::Error)
    end

    it 'raises InvalidReport, not ForbiddenXml, for plain malformed XML' do
      expect {
        DMARCator::Report.new('this is not xml')
      }.to raise_error(DMARCator::InvalidReport)
    end

    it 'keeps untrusted content out of exception messages' do
      expect {
        DMARCator::Report.new('<feedback><unclosed></feedback>')
      }.to raise_error(DMARCator::InvalidReport) do |error|
        expect(error.message).to match(/\Ainvalid DMARC XML report( at line \d+, column \d+)?\z/)
      end
    end
  end

  describe 'report shape' do
    it 'rejects well-formed XML whose root is not <feedback>' do
      xml = '<not-feedback><version>0.1</version></not-feedback>'

      expect {
        DMARCator::Report.new(xml)
      }.to raise_error(DMARCator::InvalidReport, /<feedback> root/)
    end

    it 'accepts a namespaced <feedback> root' do
      xml = '<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"><version>0.1</version></feedback>'

      expect(DMARCator::Report.new(xml).version).to eq('0.1')
    end
  end

  describe 'near-limit reports' do
    it 'parses exactly max_report_records records' do
      DMARCator.configure { |c| c.max_report_records = 3 }

      report = DMARCator::Report.new(records_xml(3))

      expect(report.records.length).to eq(3)
    end

    it 'parses a report at exactly max_xml_nodes nodes' do
      DMARCator.configure { |c| c.max_xml_nodes = 3 }

      report = DMARCator::Report.new('<feedback><a>x</a></feedback>')

      expect(report.records).to eq([])
    end

    it 'parses a report at exactly max_xml_depth' do
      DMARCator.configure { |c| c.max_xml_depth = 5 }

      report = DMARCator::Report.new(nested_xml(4))

      expect(report.records).to eq([])
    end

    it 'parses a text node at exactly max_text_length bytes' do
      DMARCator.configure { |c| c.max_text_length = 5 }

      xml = '<feedback><report_metadata><org_name>abcde</org_name></report_metadata></feedback>'

      expect(DMARCator::Report.new(xml).metadata.org_name).to eq('abcde')
    end

    it 'parses a report at exactly max_xml_attributes attributes' do
      DMARCator.configure { |c| c.max_xml_attributes = 2 }

      xml = '<feedback a="1" b="2"><version>0.1</version></feedback>'

      expect(DMARCator::Report.new(xml).version).to eq('0.1')
    end

    it 'parses exactly max_auth_results entries' do
      DMARCator.configure { |c| c.max_auth_results = 2 }

      xml = '<feedback><record><auth_results><dkim/><spf/></auth_results></record></feedback>'

      expect(DMARCator::Report.new(xml).records.first.auth_results.length).to eq(2)
    end

    it 'parses exactly max_reasons entries' do
      DMARCator.configure { |c| c.max_reasons = 2 }

      xml = '<feedback><record><row><policy_evaluated><reason/><reason/></policy_evaluated></row></record></feedback>'

      expect(DMARCator::Report.new(xml).records.first.reasons.length).to eq(2)
    end
  end

  describe 'fuzzing' do
    def random_bytes(rng, max_length = 512)
      bytes = Array.new(rng.rand(0..max_length)) { rng.rand(0..255) }
      bytes.pack('C*')
    end

    def random_balanced_xml(rng, depth = 0)
      return "x#{rng.rand(10)}" if depth > 3 || rng.rand < 0.35

      tag = %w[feedback record row auth_results policy_evaluated reason dkim spf a b].sample(random: rng)
      attrs = Array.new(rng.rand(0..2)) { " a#{rng.rand(100)}=\"v#{rng.rand(100)}\"" }.join
      children = Array.new(rng.rand(0..3)) { random_balanced_xml(rng, depth + 1) }.join

      "<#{tag}#{attrs}>#{children}</#{tag}>"
    end

    it 'never raises outside DMARCator::Error for random input' do
      rng = Random.new(20_261)

      800.times do |i|
        input = case i % 4
                when 0 then random_bytes(rng)
                when 1 then "<feedback>#{'a' * rng.rand(0..2000)}</feedback>"
                when 2 then random_balanced_xml(rng)
                else
                  "<feedback #{Array.new(rng.rand(0..30)) { |j| "a#{j}=\"v\"" }.join}>x</feedback>"
                end

        begin
          DMARCator::Report.new(input)
        rescue DMARCator::Error
          # expected: any library error is acceptable
        end
      end
    end

    it 'fuzzes the streaming pre-check and the DOM path separately' do
      rng = Random.new(7)

      300.times do
        xml = "<feedback>#{random_balanced_xml(rng)}</feedback>"
        guard = DMARCator::Internal::XmlGuard.new(xml)

        begin
          guard.check!
          guard.document
        rescue DMARCator::Error
          # expected
        end
      end
    end
  end
end
