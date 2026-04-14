require "./rule"
require "./context"

module Flaw
  # FLAW154 — path validation via string prefix check without prior
  # canonicalization. The InversePrompt class (CVE-2025-54794 shape):
  # `path.startswith(BASE)` is bypassable with symlinks or `..` unless
  # realpath/resolve ran first.
  class PathPrefixCheck < Rule
    def id : String
      "FLAW154"
    end

    def title : String
      "Prefix check without canonicalization"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A path is validated with `startswith`/`HasPrefix`/`starts_with`
      before the path is canonicalized. Symlinks or `..` segments bypass
      the check. Canonicalize (`os.path.realpath`, `Path.resolve`,
      `filepath.EvalSymlinks`, `Path::canonicalize`) before the prefix
      comparison, or compare against an absolute allowlist with the
      canonical form.
      DESC
    end

    PY_RX   = /\b([A-Za-z_][A-Za-z0-9_\.]*)\.startswith\s*\(\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*\)/
    JS_RX   = /\b([A-Za-z_$][\w$\.]*)\.startsWith\s*\(\s*([A-Za-z_$][\w$\.]*)\s*\)/
    GO_RX   = /\bstrings\.HasPrefix\s*\(\s*([A-Za-z_][\w]*)\s*,\s*([A-Za-z_][\w]*)\s*\)/
    RUST_RX = /\b([A-Za-z_][\w]*)\.starts_with\s*\(\s*&?\s*([A-Za-z_][\w]*)\s*\)/

    PATH_HINT_RX = /\b(path|dir|file|base|root|target|user|input|req|arg|uri|loc|fname|filename|location|p)\b/i

    CANON_PY_RX = /(?:os\.path\.realpath|Path\([^)]*\)\.resolve\(\)|os\.path\.abspath|pathlib\.Path\([^)]*\)\.resolve)/
    CANON_JS_RX = /(?:fs\.realpathSync|path\.resolve|fs\.promises\.realpath|\.resolve\(\))/
    CANON_GO_RX = /(?:filepath\.EvalSymlinks|filepath\.Clean|filepath\.Abs)/
    CANON_RS_RX = /\.canonicalize\(\)/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      lang_rx, canon_rx = case path
                          when .ends_with?(".py") then {PY_RX, CANON_PY_RX}
                          when .ends_with?(".go") then {GO_RX, CANON_GO_RX}
                          when .ends_with?(".rs") then {RUST_RX, CANON_RS_RX}
                          else                         {JS_RX, CANON_JS_RX}
                          end
      results = [] of Finding
      lines = source.lines
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        next unless m = line.match(lang_rx)
        var = m[1]
        next unless PATH_HINT_RX.match(var) || PATH_HINT_RX.match(m[2])
        window_start = Math.max(0, i - 15)
        window = lines[window_start..i].join('\n')
        next if canon_rx.match(window) && window.includes?(var)
        results << finding(source, path, i + 1, m.begin(0) || 0,
          "Prefix check on '#{var}' without canonicalize — symlinks/`..` bypass")
      end
      results
    end
  end
end
