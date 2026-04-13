require "./rule"

module Flaw
  class TlsVerifyDisabled < Rule
    def id : String
      "FLAW010"
    end

    def title : String
      "TLS certificate verification disabled"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      `OpenSSL::SSL::VerifyMode::NONE` or `verify_mode = OpenSSL::SSL::VerifyMode::NONE`
      silences certificate validation, making the connection vulnerable to
      active MITM. Disable only for explicit local testing — never in
      production code paths.
      DESC
    end

    PATTERNS = [
      /OpenSSL::SSL::VerifyMode::NONE/,
      /verify_mode\s*=\s*OpenSSL::SSL::VerifyMode::NONE/,
      /\.verify_mode\s*=\s*OpenSSL::SSL::VerifyMode::NONE/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "TLS verification disabled — attacker on path can MITM traffic")
            break
          end
        end
      end
      results
    end
  end
end
