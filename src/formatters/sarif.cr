require "json"

module Flaw
  module Formatters
    # SARIF 2.1.0 — compatible with GitHub Code Scanning upload.
    module Sarif
      SEV_TO_LEVEL = {
        Severity::Info     => "note",
        Severity::Low      => "note",
        Severity::Medium   => "warning",
        Severity::High     => "error",
        Severity::Critical => "error",
      }

      def self.render(findings : Array(Finding), io : IO = STDOUT) : Nil
        rules_used = findings.map(&.rule_id).uniq.map do |id|
          f = findings.find(&.rule_id.==(id)).not_nil!
          {
            "id"               => id,
            "name"             => id,
            "shortDescription" => {"text" => f.title},
            "defaultConfiguration" => {"level" => SEV_TO_LEVEL[f.severity]},
          }
        end

        results = findings.map do |f|
          {
            "ruleId"  => f.rule_id,
            "level"   => SEV_TO_LEVEL[f.severity],
            "message" => {"text" => f.message},
            "locations" => [{
              "physicalLocation" => {
                "artifactLocation" => {"uri" => f.file},
                "region"           => {"startLine" => f.line, "startColumn" => f.column},
              },
            }],
          }
        end

        {
          "$schema" => "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
          "version" => "2.1.0",
          "runs"    => [{
            "tool" => {
              "driver" => {
                "name"           => "flaw",
                "version"        => Flaw::VERSION,
                "informationUri" => "https://github.com/kdairatchi/flaw",
                "rules"          => rules_used,
              },
            },
            "results" => results,
          }],
        }.to_json(io)
        io.puts
      end
    end
  end
end
