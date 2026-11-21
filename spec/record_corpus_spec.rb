require 'spec_helper'
require 'json'
require_relative 'support/record_corpus'

#
# Golden-file regression coverage for the record parser.
#
# Records live in support/record_corpus.txt, their accepted outcomes in
# support/record_corpus.json. A failure here means a record parses differently
# than it did when the corpus was last accepted - deliberately or not. If the
# change is intentional, regenerate and review the JSON diff:
#
#   ruby -Ilib script/generate_record_corpus.rb
#
# The "anchored" example below keeps the corpus from drifting wholesale: it
# states expected behaviour independently of the recorded file.
#
RSpec.describe 'record parser corpus' do
  cases = JSON.parse(File.read(File.expand_path('support/record_corpus.json', __dir__)))

  it 'replays every recorded outcome' do
    failures = []

    cases.each do |test_case|
      { 'lenient' => false, 'strict' => true }.each do |mode, strict|
        actual = RecordCorpus.outcome(test_case.fetch('record'), strict: strict)
        expected = test_case.fetch(mode)

        next if actual == expected

        failures << "#{test_case.fetch('record').inspect} (#{mode}): " \
                    "expected #{expected.inspect}, got #{actual.inspect}"
      end
    end

    expect(failures).to be_empty, failures.first(10).join("\n")
  end

  it 'still distinguishes successful and failing parses' do
    expect(cases.count { |c| c['lenient'].key?('ok') }).to be > 100
    expect(cases.count { |c| c['lenient'].key?('error') }).to be > 5
    expect(cases.count { |c| c['strict'].key?('error') }).to be > cases.count { |c| c['lenient'].key?('error') }
  end

  it 'is anchored by hand-written expectations' do
    record = DMARCator::Record.parse('v=DMARC1; p=reject; rua=mailto:a@b.com!20m; fo=0:1')

    expect(record.p).to eq(:reject)
    expect(record.rua.first.to_s).to eq('mailto:a@b.com!20m')
    expect(record.rua.first.size).to eq(20)
    expect(record.rua.first.unit).to eq(:m)
    expect(record.fo).to eq(%w[0 1])

    expect { DMARCator::Record.parse('v=DMARC1; p=none; p=none') }
      .to raise_error(DMARCator::InvalidRecord, /duplicate/)
    expect { DMARCator::Record.parse('nonsense') }
      .to raise_error(DMARCator::InvalidRecord)
    expect { DMARCator::Record.parse('v=DMARC1; p=none; foo=bar', strict: true) }
      .to raise_error(DMARCator::InvalidRecord, /unknown/)
  end
end
