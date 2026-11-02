# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'dmarcator/version'

Gem::Specification.new do |gem|
  gem.name          = "dmarcator"
  gem.version       = DMARCator::VERSION
  gem.license       = 'MIT'
  gem.authors       = ["Noah Berman"]
  gem.email         = ["noah@noahberman.org"]
  gem.description   = "A hardened DMARC record parser and query client, forked from the Trail of Bits 'dmarc' gem."
  gem.summary       = "DMARC record parser and query client"
  gem.homepage      = "https://github.com/bermannoah/dmarcator"

  gem.metadata = {
    "source_code_uri"   => "https://github.com/bermannoah/dmarcator",
    "bug_tracker_uri"   => "https://github.com/bermannoah/dmarcator/issues",
    "changelog_uri"     => "https://github.com/bermannoah/dmarcator/blob/main/ChangeLog.md",
    "documentation_uri" => "https://rubydoc.info/gems/dmarcator",
    "rubygems_mfa_required" => "true"
  }

  gem.files         = Dir['lib/**/*.rb'] + %w[README.md ChangeLog.md LICENSE.txt]
  gem.require_paths = ["lib"]
  gem.required_ruby_version = '>= 3.3.13'

  gem.add_dependency 'nokogiri', '>= 1.19.5'
end
