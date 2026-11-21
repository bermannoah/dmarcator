require 'spec_helper'
require 'dmarcator'

RSpec.describe DMARCator::Internal::Parser do
  subject { described_class }

  describe '.parse' do
    it 'parses a minimal record' do
      expect(subject.parse('v=DMARC1;p=none')).to eq(v: :DMARC1, p: :none)
    end

    it 'parses every known tag' do
      record = 'v=DMARC1;p=reject;sp=quarantine;adkim=s;aspf=r;ri=3600;pct=50;' \
               'rf=iodef;fo=0:1:d:s;rua=mailto:a@b.com;ruf=mailto:c@d.com'

      expect(subject.parse(record)).to eq(
        v: :DMARC1, p: :reject, sp: :quarantine, adkim: :s, aspf: :r,
        ri: 3600, pct: 50, rf: :iodef, fo: %w[0 1 d s],
        rua: [DMARCator::Uri.new(URI('mailto:a@b.com'))],
        ruf: [DMARCator::Uri.new(URI('mailto:c@d.com'))]
      )
    end

    it 'coerces values to symbols and integers' do
      tags = subject.parse('v=DMARC1;p=none;pct=100;ri=86400')

      expect(tags[:p]).to eq(:none)
      expect(tags[:pct]).to eq(100)
      expect(tags[:ri]).to eq(86_400)
    end

    it 'ignores tag order' do
      expect(subject.parse('v=DMARC1; rua=mailto:a@b.com; p=none')).to eq(
        subject.parse('v=DMARC1; p=none; rua=mailto:a@b.com')
      )
    end

    it 'ignores spacing around separators and equals signs' do
      expect(subject.parse("v = DMARC1 ;\tp = none ; sp = reject\t")).to eq(
        v: :DMARC1, p: :none, sp: :reject
      )
    end

    it 'accepts a trailing separator and whitespace' do
      expect(subject.parse('v=DMARC1; p=none; ')).to eq(v: :DMARC1, p: :none)
      expect(subject.parse('v=DMARC1; p=none ')).to eq(v: :DMARC1, p: :none)
      expect(subject.parse('v=DMARC1;')).to eq(v: :DMARC1)
    end

    context 'with unknown tags' do
      it 'ignores them' do
        expect(subject.parse('v=DMARC1;p=none;foo=bar;sp=reject')).to eq(
          v: :DMARC1, p: :none, sp: :reject
        )
      end

      it 'raises in strict mode' do
        expect {
          subject.parse('v=DMARC1;p=none;foo=bar', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /unknown DMARC tag/)
      end
    end

    context 'with invalid tag values' do
      it 'ignores the tag' do
        expect(subject.parse('v=DMARC1;p=none;sp=bogus;adkim=X')).to eq(
          v: :DMARC1, p: :none
        )
      end

      it 'raises in strict mode' do
        expect {
          subject.parse('v=DMARC1;p=none;sp=bogus', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /invalid DMARC tag value/)
      end

      it 'treats a known tag with an empty value as empty' do
        expect(subject.parse('v=DMARC1;p=none;fo=')).to eq(v: :DMARC1, p: :none)

        expect {
          subject.parse('v=DMARC1;p=none;fo=', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /empty DMARC tag value/)
      end
    end

    context 'with mixed-case tags and values' do
      it 'parses them case-insensitively and normalizes the values' do
        expect(
          subject.parse('V=DMARC1; P=REJECT; SP=Quarantine; ADKIM=S; ASPF=R; RF=AFRF; FO=1:D')
        ).to eq(
          v: :DMARC1, p: :reject, sp: :quarantine, adkim: :s, aspf: :r, rf: :afrf, fo: %w[1 d]
        )
      end

      it 'keeps the version string exact' do
        expect { subject.parse('v=dmarc1; p=none') }.to raise_error(DMARCator::InvalidRecord)
      end
    end

    context 'with duplicate tags' do
      it 'raises' do
        expect {
          subject.parse('v=DMARC1;p=none;p=reject')
        }.to raise_error(DMARCator::InvalidRecord, /duplicate DMARC tag: p/)
      end

      it 'rejects a duplicate version tag' do
        expect {
          subject.parse('v=DMARC1;p=none;v=DMARC1')
        }.to raise_error(DMARCator::InvalidRecord, /duplicate DMARC version tag/)
      end
    end

    context 'with out-of-range values' do
      it 'rejects pct above 100' do
        expect {
          subject.parse('v=DMARC1;p=none;pct=999')
        }.to raise_error(DMARCator::InvalidRecord, /pct must be/)
      end

      it 'rejects ri above 2**32-1' do
        expect {
          subject.parse('v=DMARC1;p=none;ri=4294967296')
        }.to raise_error(DMARCator::InvalidRecord, /ri must be/)
      end
    end

    context 'with a malformed record' do
      it 'requires the version tag first' do
        ['', ';v=DMARC1', 'DMARC1;p=none', 'v=dmarc1;p=none',
         'v=XXXXXXXXXX'].each do |record|
          expect { subject.parse(record) }.to raise_error(DMARCator::InvalidRecord), record.inspect
        end
      end

      it 'rejects an empty tag between separators' do
        expect {
          subject.parse('v=DMARC1;p=none;;sp=reject')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'rejects a valid value followed by junk' do
        expect {
          subject.parse('v=DMARC1;p=none x')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'rejects a URI followed by junk' do
        expect {
          subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!20x')
        }.to raise_error(DMARCator::InvalidRecord)
      end

      it 'rejects input that is not a String' do
        expect { subject.parse(nil) }.to raise_error(DMARCator::InvalidRecord, /must be a String/)
        expect { subject.parse(123) }.to raise_error(DMARCator::InvalidRecord, /must be a String/)
      end

      it 'rejects records above the size limit' do
        expect {
          subject.parse("v=DMARC1;p=none;#{'a' * 5000}")
        }.to raise_error(DMARCator::InvalidRecord, /maximum size/)
      end
    end

    context 'with an unusable string encoding' do
      it 'raises rather than leaking an encoding error' do
        invalid_utf8 = "v=DMARC1; p=none\xFF".dup.force_encoding('UTF-8')
        utf16 = 'v=DMARC1; p=none'.encode('UTF-16LE')

        expect { subject.parse(invalid_utf8) }
          .to raise_error(DMARCator::InvalidRecord, /not valid UTF-8/)
        expect { subject.parse(utf16) }
          .to raise_error(DMARCator::InvalidRecord, /ASCII-compatible/)
      end

      it 'accepts ASCII-compatible encodings' do
        ['ISO-8859-1', 'Shift_JIS', 'US-ASCII'].each do |encoding|
          record = 'v=DMARC1; p=none'.encode(encoding)

          expect(subject.parse(record)[:p]).to eq(:none), encoding
        end
      end

      it 'accepts the binary strings a DNS resolver returns' do
        binary = "v=DMARC1; p=none; rua=mailto:\xFF@b.com".b

        expect(subject.parse(binary)[:p]).to eq(:none)
      end
    end

    context 'with rua and ruf lists' do
      it 'parses several URIs' do
        tags = subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com, mailto:c@d.com')

        expect(tags[:rua].map(&:to_s)).to eq(%w[mailto:a@b.com mailto:c@d.com])
      end

      it 'parses size and unit' do
        uri = subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!20m')[:rua].first

        expect(uri.size).to eq(20)
        expect(uri.unit).to eq(:m)
        expect(uri.to_s).to eq('mailto:a@b.com!20m')
      end

      it 'parses a size without a unit' do
        uri = subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!20')[:rua].first

        expect(uri.size).to eq(20)
        expect(uri.unit).to be_nil
      end

      it 'accepts every unit' do
        uri = subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!1k')[:rua].first
        expect(uri.unit).to eq(:k)
      end

      it 'accepts a case-insensitive unit and normalizes it' do
        uri = subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!1M')[:rua].first

        expect(uri.size).to eq(1)
        expect(uri.unit).to eq(:m)
      end

      it 'accepts a size that fits an unsigned 64-bit integer' do
        uri = subject.parse(
          'v=DMARC1;p=none;rua=mailto:a@b.com!18446744073709551615k'
        )[:rua].first

        expect(uri.size).to eq((2**64) - 1)
      end

      it 'ignores a size that exceeds an unsigned 64-bit integer' do
        expect(
          subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!18446744073709551616k')
        ).to eq(v: :DMARC1, p: :none)
      end

      it 'accepts an upper-case scheme' do
        uri = subject.parse('v=DMARC1;p=none;rua=MAILTO:a@b.com')[:rua].first

        expect(uri.to_s).to eq('mailto:a@b.com')
      end

      it 'ignores a list containing a non-mailto URI' do
        expect(subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com,http://evil')).to eq(
          v: :DMARC1, p: :none
        )
      end

      it 'raises on such a list in strict mode' do
        expect {
          subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com,http://evil', strict: true)
        }.to raise_error(DMARCator::InvalidRecord, /invalid DMARC tag value/)
      end

      it 'ignores an address with a control character' do
        expect(subject.parse("v=DMARC1;p=none;rua=mailto:a\nb@b.com")).to eq(
          v: :DMARC1, p: :none
        )
      end

      it 'ignores a bare bang' do
        expect(subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com!')).to eq(
          v: :DMARC1, p: :none
        )
      end

      it 'ignores a trailing comma' do
        expect(subject.parse('v=DMARC1;p=none;rua=mailto:a@b.com,')).to eq(
          v: :DMARC1, p: :none
        )
      end
    end

    context 'with the fo tag' do
      it 'parses a single option' do
        expect(subject.parse('v=DMARC1;p=none;fo=1')[:fo]).to eq(['1'])
      end

      it 'parses several options' do
        expect(subject.parse('v=DMARC1;p=none;fo=0:1:d:s')[:fo]).to eq(%w[0 1 d s])
      end

      it 'ignores an unknown option' do
        expect(subject.parse('v=DMARC1;p=none;fo=x')).to eq(v: :DMARC1, p: :none)
      end
    end

    context 'with bracket-less integers' do
      it 'ignores more than three pct digits' do
        expect(subject.parse('v=DMARC1;p=none;pct=1000')).to eq(v: :DMARC1, p: :none)
      end

      it 'ignores more than ten ri digits' do
        expect(subject.parse('v=DMARC1;p=none;ri=99999999999')).to eq(v: :DMARC1, p: :none)
      end
    end
  end
end
