require "./rule"

module Flaw
  # FLAW011 — SSRF. HTTP::Client or HTTP.get/post/etc called with an
  # interpolated URL whose host portion is user-controlled.
  class HttpUserUrl < Rule
    def id : String
      "FLAW011"
    end

    def title : String
      "Outbound HTTP request to user-controlled URL (SSRF)"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      HTTP::Client, HTTP.get/post, or similar was called with a URL built from
      user input without an allowlist of permitted hosts. An attacker can
      redirect the request at internal services (169.254.169.254, localhost,
      RFC1918). Parse the URL, check its host against an allowlist, and reject
      internal ranges before issuing the request.
      DESC
    end

    # HTTP::Client.get("https://#{host}/..."), HTTP::Client.new(host), HTTP.get(url)
    PATTERNS = [
      /\bHTTP::Client(?:\.new|\.(?:get|post|put|delete|head|patch|exec))\s*\(\s*"[^"]*\#\{/,
      /\bHTTP\.(?:get|post|put|delete|head|patch)\s*\(\s*"[^"]*\#\{/,
      /\bHTTP::Client\.new\s*\(\s*[a-z_]+\s*[,)]/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Outbound HTTP with user-controlled URL — allowlist hosts and block RFC1918/loopback/link-local before fetching")
            break
          end
        end
      end
      results
    end
  end
end
