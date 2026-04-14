require "./rule"
require "./context"

module Flaw
  # FLAW115 — permissive file permissions.
  class PermissiveChmod < Rule
    def id : String
      "FLAW115"
    end

    def title : String
      "Permissive file mode"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      World- or group-writable file modes (e.g. 0666, 0777) let any local
      account modify the file. Limit writability to the owner; use 0600,
      0640, 0644, 0700, 0750, or 0755 as appropriate.
      DESC
    end

    SAFE_MODES = %w(400 600 640 644 700 750 755)

    SHELL_RX   = /\bchmod\s+(0?[0-7]{3,4})\b/
    DOT_RX     = /\.chmod\(\s*0o?([0-7]{3,4})/
    OS_CHMOD   = /os\.chmod\([^,]+,\s*0o?([0-7]{3,4})/
    FILE_CHMOD = /File\.chmod\(\s*0o?([0-7]{3,4})/
    GO_WRITE   = /ioutil\.WriteFile\([^,]+,[^,]+,\s*0o?([0-7]{3,4})/

    PATTERNS = [SHELL_RX, DOT_RX, OS_CHMOD, FILE_CHMOD, GO_WRITE]

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path) ||
                                  path.ends_with?(".sh") || path.ends_with?(".bash") ||
                                  path.split('/').last.starts_with?("Dockerfile")
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        PATTERNS.each do |rx|
          if m = line.match(rx)
            mode = m[1].sub(/^0+/, "")
            mode = "0" if mode.empty?
            # normalise to 3 digits where possible
            canonical = mode.size == 4 ? mode[1..] : mode
            next if SAFE_MODES.includes?(canonical)
            # Only flag modes with world or group write bit set.
            next if canonical.size != 3
            group_bit = canonical[1].to_i? || 0
            world_bit = canonical[2].to_i? || 0
            if (group_bit & 2) != 0 || (world_bit & 2) != 0
              results << finding(source, path, idx, m.begin(0) || 0,
                "Permissive file mode #{m[1]} — limit to owner/group where possible")
              break
            end
          end
        end
      end
      results
    end
  end
end
