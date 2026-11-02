require 'spec_helper'
require 'dmarcator'

RSpec.describe 'DMARCator error hierarchy' do
  it 'has a common base class' do
    expect(DMARCator::Error.ancestors).to include(StandardError)

    [
      DMARCator::InvalidRecord,
      DMARCator::InvalidReport,
      DMARCator::ReportTooComplex,
      DMARCator::ForbiddenXml,
      DMARCator::ResolutionError
    ].each do |klass|
      expect(klass.ancestors).to include(DMARCator::Error)
    end
  end

  it 'does not expose the parser implementation' do
    expect(DMARCator::InvalidRecord.ancestors.map(&:name)).not_to include('Parslet::ParseFailed')
  end

  it 'lets callers rescue one base class' do
    expect { DMARCator::Record.parse('v=XXXXXXXX') }.to raise_error(DMARCator::Error)
    expect { DMARCator::Report.new('not xml') }.to raise_error(DMARCator::Error)
  end

  it 'raises InvalidRecord for parse failures' do
    expect {
      DMARCator::Record.parse('!!!')
    }.to raise_error(DMARCator::InvalidRecord, /invalid DMARC record/)
  end
end
