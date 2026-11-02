# frozen_string_literal: true

require 'spec_helper'
require 'dmarcator/report'

RSpec.describe DMARCator::Report do
  let(:example_path) { File.join(__dir__, 'support', 'complete.xml') }
  let(:google_path)  { File.join(__dir__, 'support', 'google.xml') }

  let(:xml_report)    { File.read(example_path) }
  let(:google_report) { File.read(google_path) }

  it 'has a version number' do
    expect(DMARCator::VERSION).not_to be_nil
  end

  it 'reads report version if available' do
    report = described_class.new(xml_report)
    expect(report.version).to eq('0.1')

    google = described_class.new(google_report)
    expect(google.version).to be_nil
  end

  it 'returns nil for a non-numeric report version' do
    report = described_class.new('<feedback><version>abc</version></feedback>')

    expect(report.version).to be_nil
  end

  it 'raises DMARCator::InvalidReport for malformed XML' do
    expect {
      described_class.new('this is not xml')
    }.to raise_error(DMARCator::InvalidReport)
  end

  it 'raises DMARCator::InvalidReport when the report is not a String' do
    expect { described_class.new(nil) }.to raise_error(DMARCator::InvalidReport, /must be a String/)
    expect { described_class.new(123) }.to raise_error(DMARCator::InvalidReport, /must be a String/)
  end

  it 'rejects a DTD/entity declaration as ForbiddenXml' do
    xml = <<~XML
      <?xml version="1.0"?>
      <!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
      <feedback>
        <report_metadata>
          <org_name>&xxe;</org_name>
        </report_metadata>
      </feedback>
    XML

    expect {
      described_class.new(xml)
    }.to raise_error(DMARCator::ForbiddenXml, /DTD or entity declaration/)
  end

  describe '.max_report_bytes' do
    after { DMARCator.reset_configuration! }

    it 'defaults to the configured default' do
      expect(described_class.max_report_bytes).to eq(DMARCator::Config::DEFAULT_MAX_REPORT_BYTES)
    end

    it 'delegates to DMARCator.config' do
      described_class.max_report_bytes = 1024

      expect(DMARCator.config.max_report_bytes).to eq(1024)
      expect(described_class.max_report_bytes).to eq(1024)
    end

    it 'bounds the size accepted when parsing' do
      described_class.max_report_bytes = 10

      expect {
        described_class.new("<feedback>#{'a' * 100}</feedback>")
      }.to raise_error(DMARCator::InvalidReport, /maximum size of 10 bytes/)
    end

    it 'accepts reports within the configured limit' do
      described_class.max_report_bytes = 1024

      expect(described_class.new('<feedback/>').records).to eq([])
    end
  end

  it 'returns nil for a non-numeric timestamp' do
    report = described_class.new(
      '<feedback><report_metadata><date_range><begin>notanumber</begin></date_range></report_metadata></feedback>'
    )

    expect(report.metadata.begin_at).to be_nil
  end

  it 'parses timestamps with surrounding whitespace' do
    report = described_class.new(
      '<feedback><report_metadata><date_range><begin> 1593648000 </begin></date_range></report_metadata></feedback>'
    )

    expect(report.metadata.begin_at).to eq(Time.at(1_593_648_000))
  end

  it 'returns nil for a non-numeric count' do
    report = described_class.new('<feedback><record><row><count>abc</count></row></record></feedback>')

    expect(report.records.first.count).to be_nil
  end

  it 'returns nil for a non-numeric policy pct' do
    report = described_class.new('<feedback><policy_published><pct>abc</pct></policy_published></feedback>')

    expect(report.policy.pct).to be_nil
  end

  it 'parses integers with surrounding whitespace' do
    report = described_class.new('<feedback><record><row><count> 96 </count></row></record></feedback>')

    expect(report.records.first.count).to eq(96)
  end

  it 'exposes parsed values and collections frozen' do
    report = described_class.new(xml_report)
    row = report.records.first

    expect(report.records).to be_frozen
    expect(report.version).to be_frozen
    expect(report.metadata.errors).to be_frozen
    expect(row.source_ip).to be_frozen
    expect(row.reasons).to be_frozen
    expect(row.auth_results).to be_frozen

    expect { row.source_ip << 'x' }.to raise_error(FrozenError)
    expect { report.metadata.errors << 'x' }.to raise_error(FrozenError)
  end

  it 'exposes parsed values as read-only' do
    report = described_class.new(xml_report)

    expect { report.metadata.org_name = 'x' }.to raise_error(NoMethodError)
    expect { report.policy.pct = 1 }.to raise_error(NoMethodError)
    expect { report.records.first.source_ip = 'x' }.to raise_error(NoMethodError)
    expect { report.records.first.reasons = [] }.to raise_error(NoMethodError)
  end

  it 'uses the first value when an element is duplicated' do
    report = described_class.new(<<~XML)
      <feedback>
        <report_metadata>
          <org_name>first</org_name><org_name>second</org_name>
          <date_range><begin>100</begin><begin>200</begin></date_range>
        </report_metadata>
        <policy_published>
          <pct>50</pct><pct>100</pct><p>none</p><p>reject</p>
        </policy_published>
        <record><row><count>1</count><count>2</count></row></record>
      </feedback>
    XML

    expect(report.metadata.org_name).to eq('first')
    expect(report.metadata.begin_at.to_i).to eq(100)
    expect(report.policy.pct).to eq(50)
    expect(report.policy.p).to eq('none')
    expect(report.records.first.count).to eq(1)
  end

  it 'reads report metadata' do
    report = described_class.new(xml_report)

    expect(report.metadata.org_name).to eq('google.com')
    expect(report.metadata.email).to eq('noreply-dmarc-support@google.com')
    expect(report.metadata.extra_contact_info).to eq('https://support.google.com/a/answer/2466580')
    expect(report.metadata.report_id).to eq('3114726731964606297')
    expect(report.metadata.begin_at).to eq(Time.at(1_593_648_000))
    expect(report.metadata.end_at).to eq(Time.at(1_593_734_399))
    expect(report.metadata.errors).to eq(['some error', 'another error'])
  end

  it 'reads policy published' do
    report = described_class.new(xml_report)

    expect(report.policy.domain).to eq('opserv.io')
    expect(report.policy.adkim).to eq('r')
    expect(report.policy.aspf).to eq('r')
    expect(report.policy.p).to eq('none')
    expect(report.policy.sp).to eq('none')
    expect(report.policy.pct).to eq(100)
    expect(report.policy.fo).to eq('1')
  end

  it 'reads report records' do
    report = described_class.new(xml_report)
    record = report.records.first

    expect(record.source_ip).to eq('209.85.220.69')
    expect(record.count).to eq(96)
    expect(record.disposition).to eq('none')
    expect(record.dkim).to eq('fail')
    expect(record.spf).to eq('fail')

    expect(record.reasons.count).to eq(2)
    expect(record.reasons.first.type).to eq('local_policy')
    expect(record.reasons.first.comment).to eq('arc=pass')
    expect(record.reasons.last.type).to eq('other')
    expect(record.reasons.last.comment).to eq('dkim=pass')

    expect(record.envelope_to).to eq('envelope-to.io')
    expect(record.envelope_from).to eq('envelope-from.io')
    expect(record.header_from).to eq('opserv.io')

    expect(record.auth_results.count).to eq(2)
    expect(record.auth_results.first.type).to eq('dkim')
    expect(record.auth_results.first.domain).to eq('condenast-com-tw.20150623.gappssmtp.com')
    expect(record.auth_results.first.result).to eq('pass')
    expect(record.auth_results.first.selector).to eq('20150623')
    expect(record.auth_results.last.type).to eq('spf')
    expect(record.auth_results.last.domain).to eq('condenast.com.tw')
    expect(record.auth_results.last.result).to eq('neutral')
    expect(record.auth_results.last.scope).to eq('mfrom')
  end
end
