require "./finding"
require "./config"
require "./rules/rule"
require "./rules/*"
require "./formatters/*"
require "./scanner"
require "./cli"

module Flaw
  VERSION = "0.1.0"
end

Flaw::CLI.run(ARGV)
