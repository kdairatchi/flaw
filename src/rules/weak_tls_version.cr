require "./rule"

module Flaw
  # FLAW016 — Weak TLS version pinned to SSLv3 / TLSv1.0 / TLSv1.1.
  class WeakTlsVersion < Rule
    def id : String
      "FLAW016"
    end

    def title : String
      "TLS minimum version set to a deprecated protocol"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      Pinning min_version to SSLv3, TLSv1.0, or TLSv1.1 keeps clients in
      protocols with known attacks (POODLE, BEAST). Modern services should
      require TLS 1.2+.
      DESC
    end

    PATTERNS = [
      /OpenSSL::SSL::Options::(?:ALL|SSL_V3|NO_TLSV1_2|NO_TLSV1_3)/,
      /min_version\s*=?\s*(?:OpenSSL::SSL::)?(?:SSLv3|TLSv1_0|TLSv1_1|TLSv1)\b/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Weak TLS version — require TLS 1.2 or 1.3")
            break
          end
        end
      end
      results
    end
  end
end
