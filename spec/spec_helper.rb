require 'rspec'
require 'dmarcator'

RSpec.configure do |config|
  # Specs must use RSpec.describe, so the DSL is not added to every object.
  config.disable_monkey_patching!

  # Catch examples that leak global state, such as DMARCator.configure.
  config.order = :random
end
