require "./rule"
require "./context"

module Flaw
  # FLAW141 — large base64 string literals (obfuscation, T1027).
  class Base64Blob < Rule
    def id : String
      "FLAW141"
    end

    def title : String
      "Large base64 blob"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A 500+ character base64 string literal is rarely legitimate source code.
      It is the dominant signature of payload smuggling, embedded malware, and
      encoded configuration blobs. Move to an external asset or mark intent
      with `# pragma: base64-allow`.
      DESC
    end

    BODY_RX = /["'`]([A-Za-z0-9+\/=]{500,})["'`]/

    EXTS = %w(.cr .rb .py .js .jsx .ts .tsx .go .rs .java .kt .swift .php .ex .exs .c .cpp .cc .h .hpp .json .yml .yaml)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path) || RuleContext.lock_path?(path)
      return [] of Finding unless EXTS.any? { |e| path.ends_with?(e) }
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.includes?("pragma: base64-allow")
        if m = line.match(BODY_RX)
          body = m[1]
          b64_count = body.each_char.count { |c| c.ascii_alphanumeric? || c == '+' || c == '/' || c == '=' }
          next unless b64_count * 100 >= body.size * 95
          results << finding(source, path, idx, m.begin(0) || 0,
            "Large base64 blob (#{body.size} chars) — obfuscation signal (T1027)")
        end
      end
      results
    end
  end
end
