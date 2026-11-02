require 'spec_helper'
require 'dmarcator'

#
# Pins the public API. Any addition or removal here is a deliberate decision
# that must be reflected in the ChangeLog and in the 1.0 compatibility policy,
# not something that slips in with an unrelated change.
#
RSpec.describe 'public API' do
  def instance_api(klass)
    klass.instance_methods(false).sort
  end

  describe 'DMARCator' do
    it 'exposes these module methods' do
      expect(DMARCator.singleton_methods(false).sort).to eq([
        :config, :configure, :default_resolver, :dmarc, :reset_configuration!,
        :resolv_version, :txt, :txt_records, :validate_domain,
        :validate_txt_name, :vulnerable_resolv?
      ])
    end

    it 'exposes these constants' do
      expect(DMARCator.constants(false).sort).to eq([
        :Config, :DNS_TIMEOUTS, :Error, :ForbiddenXml, :Internal,
        :InvalidRecord, :InvalidReport, :MAX_TXT_NAME_LENGTH, :Record,
        :Report, :ReportTooComplex, :ResolutionError, :Resolver, :Uri,
        :VERSION, :VULNERABLE_RESOLV
      ])
    end
  end

  describe 'DMARCator::Record' do
    it 'exposes these readers and predicates' do
      expect(instance_api(DMARCator::Record)).to eq([
        :adkim, :adkim?, :aspf, :aspf?, :fo, :fo?, :p, :p?, :pct, :pct?,
        :rf, :rf?, :ri, :ri?, :rua, :rua?, :ruf, :ruf?, :sp, :sp?, :to_h,
        :to_s, :v
      ])
    end

    it 'exposes these class methods' do
      expect(DMARCator::Record.singleton_methods(false).sort).to eq([:lookup, :parse])
    end
  end

  describe 'DMARCator::Report' do
    it 'exposes these instance methods' do
      expect(instance_api(DMARCator::Report)).to eq([:metadata, :policy, :records, :version])
    end

    it 'exposes these class methods' do
      expect(DMARCator::Report.singleton_methods(false).sort).to eq([:max_report_bytes, :max_report_bytes=])
    end
  end

  describe 'report value objects' do
    it 'exposes read-only metadata fields' do
      expect(instance_api(DMARCator::Report::Metadata)).to eq([
        :begin_at, :email, :end_at, :errors, :extra_contact_info, :org_name, :report_id
      ])
    end

    it 'exposes read-only policy fields' do
      expect(instance_api(DMARCator::Report::Policy)).to eq(
        [:adkim, :aspf, :domain, :fo, :p, :pct, :sp]
      )
    end

    it 'exposes read-only row fields' do
      expect(instance_api(DMARCator::Report::Row)).to eq([
        :auth_results, :count, :disposition, :dkim, :envelope_from,
        :envelope_to, :header_from, :reasons, :source_ip, :spf
      ])
    end

    it 'exposes read-only auth result fields' do
      expect(instance_api(DMARCator::Report::AuthResult)).to eq(
        [:domain, :result, :scope, :selector, :type]
      )
    end

    it 'exposes read-only reason fields' do
      expect(instance_api(DMARCator::Report::Reason)).to eq([:comment, :type])
    end
  end

  describe 'DMARCator::Config' do
    it 'exposes the configurable settings' do
      expect(instance_api(DMARCator::Config)).to eq([
        :max_auth_results, :max_auth_results=, :max_reasons, :max_reasons=,
        :max_report_bytes, :max_report_bytes=, :max_report_records,
        :max_report_records=, :max_text_length, :max_text_length=,
        :max_xml_attributes, :max_xml_attributes=, :max_xml_depth,
        :max_xml_depth=, :max_xml_nodes, :max_xml_nodes=, :resolver,
        :resolver=
      ])
    end
  end

  describe 'DMARCator::Uri' do
    it 'exposes these instance methods' do
      expect(instance_api(DMARCator::Uri)).to eq(
        [:==, :eql?, :hash, :size, :size?, :to_s, :unit, :unit?, :uri]
      )
    end
  end

  describe 'internals' do
    it 'keeps XML helpers private to the including classes' do
      expect(DMARCator::Internal::XmlHelper.instance_methods(false)).to be_empty
    end

    it 'keeps the error truncation helper private' do
      expect(DMARCator::Record.singleton_methods(false)).not_to include(:truncate_error_message)
    end
  end
end
