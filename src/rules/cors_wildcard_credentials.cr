require "./rule"

module Flaw
  # FLAW024 — CORS with Allow-Origin: * and Allow-Credentials: true.
  class CorsWildcardCredentials < Rule
    def id : String
      "FLAW024"
    end

    def title : String
      "CORS Allow-Origin * combined with Allow-Credentials true"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      Setting `Access-Control-Allow-Origin: *` together with
      `Access-Control-Allow-Credentials: true` is rejected by browsers
      when the wildcard is literal, but it's also a signal that the
      developer intends a permissive policy. Many frameworks work around
      the rejection by echoing back the request Origin without validating
      it — which is equivalent to wildcard-with-credentials. Maintain an
      allowlist of origins, match exactly, and only then set Credentials.
      DESC
    end

    ORIGIN_ANY    = /Access-Control-Allow-Origin.{0,40}["'*]\*["']?/
    CREDS_TRUE    = /Access-Control-Allow-Credentials.{0,40}true/i
    ECHO_ORIGIN   = /Access-Control-Allow-Origin.{0,40}(?:request\.headers\[|env\.request\.headers\[|origin\b)/i

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      # Two-tier: whole-source check for combined wildcard+creds
      if source =~ ORIGIN_ANY && source =~ CREDS_TRUE
        source.each_line.with_index(1) do |line, idx|
          next if line.lstrip.starts_with?('#')
          if m = line.match(ORIGIN_ANY)
            results << finding(source, path, idx, m.begin(0) || 0,
              "CORS Allow-Origin:* with Allow-Credentials:true — enforce an origin allowlist")
          end
        end
      end
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(ECHO_ORIGIN)
          next if line =~ /ALLOWED_ORIGINS|allowlist|includes\?/
          results << finding(source, path, idx, m.begin(0) || 0,
            "Origin header echoed without allowlist check — validate before reflecting")
        end
      end
      results
    end
  end
end
