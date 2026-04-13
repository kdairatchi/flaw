require "./rule"

module Flaw
  class OpenRedirect < Rule
    def id : String
      "FLAW007"
    end

    def title : String
      "Redirect to user-supplied URL without allowlist"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      A redirect is issued to a URL taken from a query parameter, form field, or
      header. Unvalidated redirects are used in phishing chains and to bypass
      OAuth / SSO `redirect_uri` allowlists.
      DESC
    end

    PATTERNS = [
      /\.redirect\s*\(\s*(params\[|request\.|env\[|query_params)/,
      /\.redirect\s*\([^)]*\#\{[^}]*(params|request|url|next|return)[^}]*\}[^)]*\)/,
      /\bredirect_to\s+(params\[|@?url\b|query_params)/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Redirect target from user input — validate against an allowlist of known-good hosts or paths")
            break
          end
        end
      end
      results
    end
  end
end
