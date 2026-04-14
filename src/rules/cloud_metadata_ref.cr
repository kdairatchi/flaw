require "./rule"
require "./context"

module Flaw
  # FLAW136 — Cloud instance metadata endpoint reference.
  class CloudMetadataRef < Rule
    def id : String
      "FLAW136"
    end

    def title : String
      "Cloud metadata endpoint"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Hardcoded references to cloud instance metadata endpoints
      (169.254.169.254, metadata.google.internal, metadata.azure.com)
      often mark either an SSRF exploit payload or tooling that reads
      instance credentials — both need a review.
      DESC
    end

    EXT = %w(.cr .rb .py .js .jsx .ts .tsx .mjs .cjs .go .rs .java .kt .swift .php .ex .exs .c .cpp .cc .h .hpp .yml .yaml .tf .json)

    RX = /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Cloud instance metadata endpoint reference — SSRF target or credentials exfil vector")
        end
      end
      results
    end
  end
end
