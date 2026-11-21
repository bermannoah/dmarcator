# frozen_string_literal: true

require 'rubygems'

begin
  require 'bundler/setup'
rescue LoadError => error
  warn error.message
  warn "Run `gem install bundler` to install Bundler."
  exit 1
end

require 'rake'
require 'rubygems/tasks'
Gem::Tasks.new

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new

task test: :spec
task default: :spec

require 'yard'
YARD::Rake::YardocTask.new
task doc: :yard
