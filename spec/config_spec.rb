require 'spec_helper'
require 'dmarcator'

RSpec.describe DMARCator::Config do
  after { DMARCator.reset_configuration! }

  describe '.config' do
    it 'returns a Config' do
      expect(DMARCator.config).to be_a(described_class)
    end

    it 'is memoized' do
      expect(DMARCator.config).to be(DMARCator.config)
    end
  end

  describe '.configure' do
    it 'yields the configuration and returns it' do
      yielded = nil

      result = DMARCator.configure { |config| yielded = config }

      expect(yielded).to be(DMARCator.config)
      expect(result).to be(DMARCator.config)
    end

    it 'returns the configuration without a block' do
      expect(DMARCator.configure).to be(DMARCator.config)
    end
  end

  describe '.default_resolver' do
    it 'uses the configured resolver object' do
      resolver = double('resolver')
      DMARCator.configure { |config| config.resolver = resolver }

      expect(DMARCator.default_resolver).to be(resolver)
    end

    it 'calls a configured callable for each lookup' do
      resolvers = [double('one'), double('two')]
      calls = 0
      DMARCator.configure { |config| config.resolver = -> { calls += 1; resolvers[calls - 1] } }

      expect(DMARCator.default_resolver).to be(resolvers[0])
      expect(DMARCator.default_resolver).to be(resolvers[1])
    end

    it 'takes precedence over the environment' do
      resolver = double('resolver')
      DMARCator.configure { |config| config.resolver = resolver }

      allow(DMARCator::Resolver).to receive(:build)

      expect(DMARCator.default_resolver).to be(resolver)
      expect(DMARCator::Resolver).not_to have_received(:build)
    end

    it 'falls back to the environment when unconfigured' do
      allow(DMARCator::Resolver).to receive(:build).and_return(:from_env)

      expect(DMARCator.default_resolver).to eq(:from_env)
    end
  end

  describe 'max_report_bytes' do
    after { DMARCator.reset_configuration! }

    it 'defaults to the library default' do
      expect(DMARCator.config.max_report_bytes).to eq(described_class::DEFAULT_MAX_REPORT_BYTES)
    end

    it 'accepts a positive Integer' do
      DMARCator.configure { |config| config.max_report_bytes = 1024 }

      expect(DMARCator.config.max_report_bytes).to eq(1024)
    end

    it 'restores the default when set to nil' do
      DMARCator.configure { |config| config.max_report_bytes = 1024 }
      DMARCator.configure { |config| config.max_report_bytes = nil }

      expect(DMARCator.config.max_report_bytes).to eq(described_class::DEFAULT_MAX_REPORT_BYTES)
    end

    it 'rejects values that are not positive Integers' do
      [0, -1, '1024', 1.5].each do |value|
        expect {
          DMARCator.configure { |config| config.max_report_bytes = value }
        }.to raise_error(ArgumentError, /max_report_bytes/)
      end
    end
  end

  describe 'XML report complexity limits' do
    after { DMARCator.reset_configuration! }

    limits = {
      max_report_records: described_class::DEFAULT_MAX_REPORT_RECORDS,
      max_xml_nodes: described_class::DEFAULT_MAX_XML_NODES,
      max_xml_depth: described_class::DEFAULT_MAX_XML_DEPTH,
      max_text_length: described_class::DEFAULT_MAX_TEXT_LENGTH,
      max_xml_attributes: described_class::DEFAULT_MAX_XML_ATTRIBUTES,
      max_auth_results: described_class::DEFAULT_MAX_AUTH_RESULTS,
      max_reasons: described_class::DEFAULT_MAX_REASONS
    }

    limits.each do |setting, default|
      describe setting.to_s do
        it 'defaults to the library default' do
          expect(DMARCator.config.public_send(setting)).to eq(default)
        end

        it 'accepts a positive Integer' do
          DMARCator.configure { |config| config.public_send("#{setting}=", 42) }

          expect(DMARCator.config.public_send(setting)).to eq(42)
        end

        it 'restores the default when set to nil' do
          DMARCator.configure { |config| config.public_send("#{setting}=", 42) }
          DMARCator.configure { |config| config.public_send("#{setting}=", nil) }

          expect(DMARCator.config.public_send(setting)).to eq(default)
        end

        it 'rejects values that are not positive Integers' do
          [0, -1, '1024', 1.5].each do |value|
            expect {
              DMARCator.configure { |config| config.public_send("#{setting}=", value) }
            }.to raise_error(ArgumentError, /#{setting}/)
          end
        end
      end
    end
  end

  describe '.reset_configuration!' do
    it 'discards configured values' do
      DMARCator.configure { |config| config.resolver = double('resolver') }

      DMARCator.reset_configuration!

      expect(DMARCator.config.resolver).to be_nil
    end
  end
end
