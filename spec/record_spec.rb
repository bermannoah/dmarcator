require 'spec_helper'
require 'dmarcator/record'

describe DMARCator::Record do
  describe '#initialize' do
    let(:attributes) do
      {
        v: :DMARC1,
        p: :none,
        adkim: :r
      }
    end

    subject { described_class.new(attributes) }

    it 'assigns the fields to its properties' do
      expect(subject.v).to     be :DMARC1
      expect(subject.p).to     be :none
      expect(subject.adkim).to be :r
    end

    it 'gives "sp" the same value as "p" if undefined' do
      expect(subject.sp).to be :none
    end

    it "falls back to p when sp is omitted" do
      record = DMARCator::Record.parse("v=DMARC1; p=reject")
      expect(record.sp).to eq(:reject)
    end

    it "uses sp when present" do
      record = DMARCator::Record.parse("v=DMARC1; p=none; sp=reject")
      expect(record.sp).to eq(:reject)
    end
  end

  context 'with default values' do
    subject { described_class.new(v: :DMARC1) }

    describe "#adkim" do
      it "should return :r" do
        expect(subject.adkim).to be == :r
      end
    end

    describe "#aspf" do
      it "should return :r" do
        expect(subject.aspf).to be == :r
      end
    end

    describe "#fo" do
      it "should return ['0']" do
        expect(subject.fo).to be == ['0']
      end
    end

    describe "#pct" do
      it "should return 100" do
        expect(subject.pct).to be == 100
      end
    end

    describe "#rf" do
      it "should return afrf" do
        expect(subject.rf).to be == :afrf
      end
    end

    describe "#ri" do
      it "should return 86400" do
        expect(subject.ri).to be == 86400
      end
    end
  end

  describe '.parse' do
    subject { described_class }

    context 'with a valid record' do
      it 'parse and returns a record' do
        rec = subject.parse('v=DMARC1; p=quarantine')

        expect(rec).to be_a DMARCator::Record
        expect(rec.p).to eq :quarantine
      end

      it 'parses case-insensitive mailto URIs' do
        rec = subject.parse('v=DMARC1; p=none; rua=MAILTO:a@b.com')

        expect(rec.rua).to eq([DMARCator::Uri.new(URI('mailto:a@b.com'))])
      end

      it 'parses a mailto URI with a plus tag' do
        rec = subject.parse('v=DMARC1; p=none; rua=mailto:user+tag@example.com')

        expect(rec.rua).to eq([DMARCator::Uri.new(URI('mailto:user+tag@example.com'))])
      end
    end

    it 'exposes its list attributes frozen' do
      rec = subject.parse('v=DMARC1; p=none; rua=mailto:a@b.com; fo=0:1')

      expect(rec.rua).to be_frozen
      expect(rec.fo).to be_frozen
      expect { rec.rua << :extra }.to raise_error(FrozenError)
    end

    context 'with an invalid record' do
      it 'raises an DMARCator::InvalidRecord error' do
        expect {
          subject.parse('v=XXXXXXXXXX')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'raises when the p tag is missing' do
        expect {
          subject.parse('v=DMARC1')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'raises when pct is out of range' do
        expect {
          subject.parse('v=DMARC1; p=none; pct=999')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'raises when tags are duplicated' do
        expect {
          subject.parse('v=DMARC1; p=none; p=reject')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'raises when the record is not a String' do
        expect { subject.parse(nil) }.to raise_error(DMARCator::InvalidRecord, /must be a String/)
        expect { subject.parse(123) }.to raise_error(DMARCator::InvalidRecord, /must be a String/)
      end
    end

    context 'with a non-mailto rua URI' do
      it 'ignores the invalid rua tag' do
        rec = subject.parse('v=DMARC1; p=none; rua=http://169.254.169.254/?x=1')

        expect(rec).to be_a DMARCator::Record
        expect(rec.rua).to be_nil
      end

      it 'ignores a list containing an invalid rua URI' do
        rec = subject.parse('v=DMARC1; p=none; rua=mailto:a@b.com,http://evil')

        expect(rec).to be_a DMARCator::Record
        expect(rec.rua).to be_nil
      end

      it 'ignores a rua URI with a control character' do
        rec = subject.parse("v=DMARC1; p=none; rua=mailto:a\nb@example.com")

        expect(rec).to be_a DMARCator::Record
        expect(rec.rua).to be_nil
      end
    end

    context 'in strict mode' do
      it 'parses a valid record' do
        rec = subject.parse('v=DMARC1; p=none; pct=50; rua=mailto:a@b.com', strict: true)

        expect(rec.pct).to eq(50)
      end

      it 'raises on unknown tags' do
        expect {
          subject.parse('v=DMARC1; p=none; foo=bar', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /unknown DMARC tag/)
      end

      it 'raises on invalid tag values' do
        expect {
          subject.parse('v=DMARC1; p=none; pct=abc', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /invalid DMARC tag value/)
      end

      it 'raises on a rua list containing an invalid URI' do
        expect {
          subject.parse('v=DMARC1; p=none; rua=mailto:a@b.com,http://evil', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /invalid DMARC tag value/)
      end

      it 'raises on a rua URI with a control character' do
        expect {
          subject.parse("v=DMARC1; p=none; rua=mailto:a\nb@example.com", strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /invalid DMARC tag value/)
      end
    end
  end

  describe ".lookup" do
    subject { described_class }

    context "when the domain has a DMARC record" do
      it "looks up and parses the DMARC record" do
        expect(DMARCator).to receive(:dmarc)
          .with("google.com", resolver: anything)
          .and_return("v=DMARC1; p=reject")

        record = subject.lookup("google.com")

        expect(record).to be_kind_of(DMARCator::Record)
        expect(record.v).to be == :DMARC1
      end
    end

    context "when the domain has no DMARC record" do
      it "returns nil" do
        expect(DMARCator).to receive(:dmarc)
          .with("foobar.heythere", resolver: anything)
          .and_return(nil)

        expect(subject.lookup('foobar.heythere')).to be_nil
      end
    end
  end

  shared_examples "question mark method" do |field,value|
    describe "#{field}?" do
      context "when #{field} is set" do
        subject do
          described_class.new(v: :DMARC1, field => value)
        end

        it { expect(subject.send(:"#{field}?")).to be(true) }
      end

      context "when #{field} is omitted" do
        subject { described_class.new(v: :DMARC1) }

        it { expect(subject.send(:"#{field}?")).to be(false) }
      end
    end
  end

  include_examples "question mark method", :adkim, :r
  include_examples "question mark method", :aspf, :r
  include_examples "question mark method", :fo, %w[0 1 d]
  include_examples "question mark method", :p, :reject
  include_examples "question mark method", :pct, 100
  include_examples "question mark method", :rf, :afrf
  include_examples "question mark method", :ri, 86400
  include_examples "question mark method", :rua, [URI("mailto:bob@example.com")]
  include_examples "question mark method", :ruf, [URI("mailto:bob@example.com")]
  include_examples "question mark method", :sp, :reject

  describe "#sp?" do
    context "when sp is set" do
    end
  end

  describe "#to_h" do
    let(:v) { :DMARC1 }
    let(:p) { :reject }
    let(:rua) { [URI.parse('mailto:d@rua.agari.com')] }
    let(:ruf) { [URI.parse('mailto:d@rua.agari.com')] }
    let(:fo)  { %w[0 1 d] }

    subject do
      described_class.new(
        v: v,
        p: p,
        rua: rua,
        ruf: ruf,
        fo: fo
      )
    end

    it "should return a Hash" do
      expect(subject.to_h).to be_kind_of(Hash)
    end

    it "should only include fields that have values" do
      expect(subject.to_h).to be == {
        v: v,
        p: p,
        rua: rua,
        ruf: ruf,
        fo: fo
      }
    end
  end

  describe "#to_s" do
    let(:v) { :DMARC1 }
    let(:p) { :reject }
    let(:rua) { [URI.parse('mailto:d@rua.agari.com')] }
    let(:ruf) { [URI.parse('mailto:d@rua.agari.com')] }
    let(:fo)  { %w[0 1 d] }

    subject do
      described_class.new(
        v: v,
        p: p,
        rua: rua,
        ruf: ruf,
        fo: fo
      )
    end

    it "should convert the record to a String" do
      expect(subject.to_s).to be == "v=#{v}; p=#{p}; rua=#{rua[0]}; ruf=#{ruf[0]}; fo=#{fo[0]}:#{fo[1]}:#{fo[2]}"
    end

    it "preserves report URI sizes and units" do
      record = DMARCator::Record.parse(
        "v=DMARC1; p=reject; rua=mailto:d@example.com!10m; ruf=mailto:f@example.com!5g"
      )

      expect(record.to_s).to include("rua=mailto:d@example.com!10m")
      expect(record.to_s).to include("ruf=mailto:f@example.com!5g")
    end

    it "round-trips report URI sizes and units" do
      record = DMARCator::Record.parse(
        "v=DMARC1; p=reject; rua=mailto:d@example.com!10m"
      )

      expect(DMARCator::Record.parse(record.to_s).to_h).to eq(record.to_h)
    end
  end
end
