require "./rule"

module Flaw
  # FLAW018 — Secret-named variable interpolated into a log or print call.
  class SecretInLog < Rule
    def id : String
      "FLAW018"
    end

    def title : String
      "Secret-named value written to log or stdout"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      A value whose name suggests a credential (password, token, api_key,
      secret, session, cookie, authorization) was interpolated into a log
      message or `puts`. Logs are frequently collected by third-party
      pipelines and indexed — do not include raw secrets. Log the value's
      prefix, hash, or the fact that it exists.
      DESC
    end

    SECRET = /\#\{([^}]*\b(?:password|passwd|pwd|token|api[_-]?key|secret|authorization|session|cookie|bearer)\b[^}]*)\}/i
    SINKS  = /\b(Log\.(?:trace|debug|info|notice|warn|error|fatal)|puts|print|p|pp|STDOUT\.puts|STDERR\.puts)\b/
    # Presence/prefix/hash references are not leaks.
    SAFE_SUFFIX = /\.(?:nil\?|size|length|empty\?|hash|digest|hexdigest|bytesize|to_s\.size)|\[\d+,\s*\d+\]|\[0\.\.\d+\]/

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        next unless line =~ SINKS
        line.scan(SECRET) do |m|
          inside = m[1]
          next if inside =~ SAFE_SUFFIX
          next if inside =~ /^\!|present/i
          results << finding(source, path, idx, m.begin(0) || 0,
            "Secret-named value in a log/print — log a prefix or fingerprint, never the raw value")
        end
      end
      results
    end
  end
end
