# frozen_string_literal: true

require 'spec_helper'

#
# Keeps the release metadata in step: the version in lib/dmarcator/version.rb
# must have a ChangeLog section and a SECURITY.md support row.
#
RSpec.describe 'release metadata' do
  let(:root)    { File.expand_path('..', __dir__) }
  let(:version) { DMARCator::VERSION }

  it 'has a ChangeLog section for the current version' do
    changelog = File.read(File.join(root, 'ChangeLog.md'), encoding: 'UTF-8')

    expect(changelog).to match(/^### #{Regexp.escape(version)} /)
  end

  it 'lists the current version in the supported versions table' do
    security = File.read(File.join(root, 'SECURITY.md'), encoding: 'UTF-8')

    expect(security).to match(/^\| #{Regexp.escape(version)}\s+\|/)
  end
end
