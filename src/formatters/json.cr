require "json"

module Flaw
  module Formatters
    module JsonFmt
      def self.render(findings : Array(Finding), io : IO = STDOUT) : Nil
        {
          "version"  => Flaw::VERSION,
          "count"    => findings.size,
          "findings" => findings,
        }.to_json(io)
        io.puts
      end
    end
  end
end
