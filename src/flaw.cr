require "./finding"
require "./config"
require "./entropy"
require "./source_prep"
require "./suppression"
require "./baseline"
require "./rules/rule"
require "./ast_backend"
require "./rules/*"
require "./formatters/*"
require "./scanner"
require "./lint_rules"
require "./doctor"
require "./cli"

module Flaw
  VERSION = "0.1.0"
end
