require 'spec_helper'
require 'dmarcator'

describe DMARCator do
  subject { described_class }

  let(:txt_class) { Resolv::DNS::Resource::IN::TXT }
  let(:resolver)  { double("resolver") }

  def txt(strings)
    instance_double(txt_class, strings: strings)
  end

  describe ".dmarc" do
    it "returns the DMARC TXT record" do
      allow(resolver).to receive(:getresources)
        .with("_dmarc.google.com", txt_class)
        .and_return([txt(["v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"])])

      expect(subject.dmarc("google.com", resolver: resolver)).to eq(
        "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"
      )
    end

    it "ignores non-DMARC TXT records" do
      allow(resolver).to receive(:getresources)
        .with("_dmarc.google.com", txt_class)
        .and_return([
          txt(["not a dmarc record"]),
          txt(["v=DMARC1; p=reject"])
        ])

      expect(subject.dmarc("google.com", resolver: resolver)).to eq("v=DMARC1; p=reject")
    end

    it "returns nil when multiple DMARC records exist" do
      allow(resolver).to receive(:getresources)
        .with("_dmarc.google.com", txt_class)
        .and_return([txt(["v=DMARC1; p=none"]), txt(["v=DMARC1; p=reject"])])

      expect(subject.dmarc("google.com", resolver: resolver)).to be_nil
    end

    it "returns nil when no DMARC record exists" do
      allow(resolver).to receive(:getresources).and_return([])

      expect(subject.dmarc("google.com", resolver: resolver)).to be_nil
    end

    it "returns nil when only non-DMARC TXT records exist" do
      allow(resolver).to receive(:getresources).and_return([txt(["hello world"])])

      expect(subject.dmarc("google.com", resolver: resolver)).to be_nil
    end

    it "recognizes a case-insensitive version tag" do
      allow(resolver).to receive(:getresources).and_return([txt(["V=DMARC1; P=REJECT"])])

      expect(subject.dmarc("google.com", resolver: resolver)).to eq("V=DMARC1; P=REJECT")
    end

    it "accepts whitespace around the version tag" do
      allow(resolver).to receive(:getresources).and_return([txt(["v = DMARC1 ; p=reject"])])

      expect(subject.dmarc("google.com", resolver: resolver)).to eq("v = DMARC1 ; p=reject")
    end

    it "requires the version string to be exact" do
      allow(resolver).to receive(:getresources).and_return([txt(["v=dmarc1; p=reject"])])

      expect(subject.dmarc("google.com", resolver: resolver)).to be_nil
    end

    it "raises ResolutionError when the resolver fails" do
      allow(resolver).to receive(:getresources)
        .and_raise(Resolv::ResolvError, "DNS resolv timeout: _dmarc.google.com")

      expect {
        subject.dmarc("google.com", resolver: resolver)
      }.to raise_error(DMARCator::ResolutionError, /DNS TXT lookup failed.*timeout/)
    end

    it "rejects invalid domains" do
      expect { subject.dmarc("foo bar") }.to raise_error(ArgumentError)
    end

    it "does not reconfigure an injected resolver" do
      expect(resolver).not_to receive(:timeouts=)
      allow(resolver).to receive(:getresources).and_return([])

      subject.dmarc("google.com", resolver: resolver)
    end
  end

  describe ".txt" do
    it "returns every TXT record unfiltered" do
      allow(resolver).to receive(:getresources)
        .with("example.com", txt_class)
        .and_return([
          txt(["v=spf1 include:_spf.example.com -all"]),
          txt(["google-site-verification=abc"]),
          txt(["v=DMARC1; p=none"])
        ])

      expect(subject.txt("example.com", resolver: resolver)).to eq([
        "v=spf1 include:_spf.example.com -all",
        "google-site-verification=abc",
        "v=DMARC1; p=none"
      ])
    end

    it "joins multi-chunk records without a separator" do
      allow(resolver).to receive(:getresources)
        .and_return([txt(["v=spf1 include:_spf.example.com", " -all"])])

      expect(subject.txt("example.com", resolver: resolver)).to eq(
        ["v=spf1 include:_spf.example.com -all"]
      )
    end

    it "preserves order and duplicates" do
      allow(resolver).to receive(:getresources)
        .and_return([txt(["v=DMARC1; p=none"]), txt(["v=DMARC1; p=none"])])

      expect(subject.txt("_dmarc.example.com", resolver: resolver)).to eq(
        ["v=DMARC1; p=none", "v=DMARC1; p=none"]
      )
    end

    it "returns an empty array when the name has no records" do
      allow(resolver).to receive(:getresources).and_return([])

      expect(subject.txt("_dmarc.example.com", resolver: resolver)).to eq([])
    end

    it "returns an empty string for an empty TXT record" do
      allow(resolver).to receive(:getresources).and_return([txt([""])])

      expect(subject.txt("example.com", resolver: resolver)).to eq([""])
    end

    it "accepts service labels with underscores" do
      allow(resolver).to receive(:getresources).and_return([])

      subject.txt("_dmarc.example.com", resolver: resolver)
      subject.txt("s1._domainkey.example.com", resolver: resolver)

      expect(resolver).to have_received(:getresources).twice
    end

    it "accepts an absolute name with a trailing dot" do
      allow(resolver).to receive(:getresources).and_return([])

      expect(subject.txt("_dmarc.example.com.", resolver: resolver)).to eq([])
    end

    it "raises ResolutionError when the resolver fails" do
      allow(resolver).to receive(:getresources)
        .and_raise(Resolv::ResolvError, "DNS resolv timeout: _dmarc.example.com")

      expect {
        subject.txt("_dmarc.example.com", resolver: resolver)
      }.to raise_error(DMARCator::ResolutionError, /DNS TXT lookup failed.*timeout/)
    end

    it "propagates ResolutionError from encrypted transports" do
      allow(resolver).to receive(:getresources)
        .and_raise(DMARCator::ResolutionError, "DoH endpoint returned HTTP 500")

      expect {
        subject.txt("_dmarc.example.com", resolver: resolver)
      }.to raise_error(DMARCator::ResolutionError, /HTTP 500/)
    end

    it "does not reconfigure an injected resolver" do
      expect(resolver).not_to receive(:timeouts=)
      allow(resolver).to receive(:getresources).and_return([])

      subject.txt("_dmarc.example.com", resolver: resolver)
    end

    it "rejects empty and non-String names" do
      expect { subject.txt("") }.to raise_error(ArgumentError, /invalid TXT name/)
      expect { subject.txt(nil) }.to raise_error(ArgumentError, /invalid TXT name/)
    end

    it "rejects over-long labels and names" do
      expect { subject.txt("#{'a' * 64}.example.com") }.to raise_error(ArgumentError)
      expect { subject.txt("#{'a' * 63}.#{'a' * 63}.#{'a' * 63}.#{'a' * 62}") }.to raise_error(ArgumentError)
    end

    describe "an injected Resolv::DNS" do
      it "rejects one that would swallow timeout errors" do
        expect {
          subject.txt("_dmarc.example.com", resolver: Resolv::DNS.new)
        }.to raise_error(ArgumentError, /raise_timeout_errors: true/)
      end

      it "accepts one constructed to raise on timeout" do
        fail_closed = Resolv::DNS.new(raise_timeout_errors: true)
        allow(fail_closed).to receive(:getresources)
          .with("_dmarc.example.com", txt_class)
          .and_return([txt(["v=DMARC1; p=none"])])

        expect(subject.txt("_dmarc.example.com", resolver: fail_closed))
          .to eq(["v=DMARC1; p=none"])
      end
    end
  end

  describe ".txt_records" do
    it "returns the resource records unfiltered, in order" do
      first  = txt(["v=spf1 -all"])
      second = txt(["v=DMARC1; p=none"])
      allow(resolver).to receive(:getresources).and_return([first, second])

      expect(subject.txt_records("example.com", resolver: resolver)).to eq([first, second])
    end

    it "exposes the record strings and ttl for caching" do
      record = txt(["v=DMARC1; p=none"])
      allow(record).to receive(:ttl).and_return(300)
      allow(resolver).to receive(:getresources).and_return([record])

      result = subject.txt_records("_dmarc.example.com", resolver: resolver)

      expect(result.first.strings).to eq(["v=DMARC1; p=none"])
      expect(result.first.ttl).to eq(300)
    end

    it "returns an empty array when the name has no records" do
      allow(resolver).to receive(:getresources).and_return([])

      expect(subject.txt_records("_dmarc.example.com", resolver: resolver)).to eq([])
    end

    it "agrees with txt" do
      allow(resolver).to receive(:getresources)
        .and_return([txt(["a"]), txt(["b", "c"])])

      expect(subject.txt_records("example.com", resolver: resolver).map { |r| r.strings.join })
        .to eq(subject.txt("example.com", resolver: resolver))
    end

    it "raises ResolutionError when the resolver fails" do
      allow(resolver).to receive(:getresources)
        .and_raise(Resolv::ResolvError, "DNS resolv timeout: _dmarc.example.com")

      expect {
        subject.txt_records("_dmarc.example.com", resolver: resolver)
      }.to raise_error(DMARCator::ResolutionError, /DNS TXT lookup failed/)
    end

    it "rejects invalid names" do
      expect { subject.txt_records("") }.to raise_error(ArgumentError, /invalid TXT name/)
    end
  end

  describe ".validate_domain" do
    it "accepts a valid domain" do
      expect(subject.validate_domain("example.com")).to eq("example.com")
    end

    it "rejects a label longer than 63 octets" do
      expect {
        subject.validate_domain("#{'a' * 64}.com")
      }.to raise_error(ArgumentError)
    end

    it "accepts a 63-octet label" do
      domain = "#{'a' * 63}.com"

      expect(subject.validate_domain(domain)).to eq(domain)
    end

    it "rejects a domain longer than 246 octets" do
      domain = "#{'a' * 62}.#{'a' * 62}.#{'a' * 62}.#{'a' * 58}"

      expect { subject.validate_domain(domain) }.to raise_error(ArgumentError)
    end

    it "accepts a domain at the 246-octet limit" do
      domain = "#{'a' * 62}.#{'a' * 62}.#{'a' * 62}.#{'a' * 57}"

      expect(subject.validate_domain(domain)).to eq(domain)
    end

    it "rejects a non-string domain" do
      expect { subject.validate_domain(123) }.to raise_error(ArgumentError)
    end

    it "rejects a label with a leading hyphen" do
      expect { subject.validate_domain("-foo.com") }.to raise_error(ArgumentError)
    end

    it "rejects a label with a trailing hyphen" do
      expect { subject.validate_domain("foo-.com") }.to raise_error(ArgumentError)
    end

    it "accepts a hyphen within a label" do
      expect(subject.validate_domain("foo-bar.com")).to eq("foo-bar.com")
    end

    it "rejects an underscore in the domain" do
      expect { subject.validate_domain("foo_bar.com") }.to raise_error(ArgumentError)
    end
  end

  describe ".vulnerable_resolv?" do
    it "is true for resolv 0.3.1 and earlier" do
      allow(subject).to receive(:resolv_version).and_return("0.3.1")

      expect(subject.vulnerable_resolv?).to be(true)
    end

    it "is false for resolv 0.3.2" do
      allow(subject).to receive(:resolv_version).and_return("0.3.2")

      expect(subject.vulnerable_resolv?).to be(false)
    end

    it "is true for resolv 0.4.0 through 0.7.1" do
      allow(subject).to receive(:resolv_version).and_return("0.7.1")

      expect(subject.vulnerable_resolv?).to be(true)
    end

    it "is false for resolv 0.7.2 and later" do
      allow(subject).to receive(:resolv_version).and_return("0.7.2")

      expect(subject.vulnerable_resolv?).to be(false)
    end

    it "is false when the version is unknown" do
      allow(subject).to receive(:resolv_version).and_return(nil)

      expect(subject.vulnerable_resolv?).to be(false)
    end

    it "is false when the version is not a valid gem version" do
      allow(subject).to receive(:resolv_version).and_return("custom-build")

      expect(subject.vulnerable_resolv?).to be(false)
    end
  end
end
