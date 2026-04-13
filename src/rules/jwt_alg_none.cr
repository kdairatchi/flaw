require "./rule"

module Flaw
  # FLAW023 — JWT alg:none or signature verification disabled.
  class JwtAlgNone < Rule
    def id : String
      "FLAW023"
    end

    def title : String
      "JWT with alg:none or verification disabled"
    end

    def default_severity : Severity
      Severity::Critical
    end

    def description : String
      <<-DESC
      A JWT is being created or decoded with `alg: "none"`, `algorithm: nil`,
      or `verify: false`. Any attacker-crafted token with `{"alg":"none"}`
      in the header is then accepted as valid. Always verify with a
      specific algorithm (HS256/RS256/ES256) and keep the key secret.
      DESC
    end

    PATTERNS = [
      /\balg(?:orithm)?:\s*(?:"none"|'none'|nil|JWT::Algorithm::None)/i,
      /JWT\.decode\s*\([^)]*verify:\s*false/,
      /JWT\.decode\s*\([^)]*\bnil\s*,\s*(?:"none"|'none')/i,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "JWT signature not enforced — pin an algorithm (HS256/RS256) and verify")
            break
          end
        end
      end
      results
    end
  end
end
