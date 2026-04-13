require "./rule"

module Flaw
  # FLAW019 — Cookie set without Secure / HttpOnly / SameSite flags.
  class InsecureCookie < Rule
    def id : String
      "FLAW019"
    end

    def title : String
      "Cookie set without Secure / HttpOnly / SameSite flags"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      A cookie was created or set without Secure, HttpOnly, and SameSite
      attributes. Session cookies must be HttpOnly (blocks JS theft via XSS),
      Secure (blocks leakage over HTTP), and SameSite=Lax or Strict (blocks
      CSRF via cross-site requests).
      DESC
    end

    # HTTP::Cookie.new("name", "value") without the flags passed
    COOKIE_NEW = /\bHTTP::Cookie\.new\s*\(/

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        next unless m = line.match(COOKIE_NEW)
        # look at this line + next 3 for flags
        lines = source.split('\n')
        window = lines[(idx - 1)...[idx + 3, lines.size].min].join(' ')
        missing = [] of String
        missing << "secure"    unless window =~ /secure:\s*true|\.secure\s*=\s*true/
        missing << "http_only" unless window =~ /http_only:\s*true|\.http_only\s*=\s*true/
        missing << "samesite"  unless window =~ /samesite:|\.samesite\s*=/i
        next if missing.empty?
        results << finding(source, path, idx, m.begin(0) || 0,
          "Cookie missing: #{missing.join(", ")} — set secure, http_only, samesite")
      end
      results
    end
  end
end
