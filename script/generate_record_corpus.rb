#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Regenerates spec/support/record_corpus.json from the records in
# spec/support/record_corpus.txt, using the current parser.
#
# Run this only when a parser change is intentional:
#
#   ruby -Ilib script/generate_record_corpus.rb
#
# Then review the diff of the JSON file in the commit. A change there means a
# record is parsed differently.
#
require 'json'

require 'dmarcator'
require_relative '../spec/support/record_corpus'

root = File.expand_path('..', __dir__)
records_path = File.join(root, 'spec', 'support', 'record_corpus.txt')
output_path = File.join(root, 'spec', 'support', 'record_corpus.json')

records = RecordCorpus.records(records_path)
cases = RecordCorpus.cases(records)

File.write(output_path, "#{JSON.pretty_generate(cases)}\n")

puts "wrote #{cases.size} cases to #{output_path}"
