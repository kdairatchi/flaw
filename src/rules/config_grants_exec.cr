require "./rule"
require "./context"

module Flaw
  # FLAW150 — project-local AI/tool config grants execution (CVE-2025-59536
  # class). `.claude/settings.json`, `.cursor/rules`, hooks that auto-run
  # shell on repo open turn a `git clone` into arbitrary code execution.
  class ConfigGrantsExec < Rule
    def id : String
      "FLAW150"
    end

    def title : String
      "Project-local config grants execution"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A `.claude/`, `.cursor/`, `.windsurfrules`, `.continuerc`, or
      `.vscode/settings.json` file in the repo grants exec-like perms —
      Bash(*) wildcard allowlist, shell `command:` values, hook scripts,
      or terminal automation profiles. Any dev who clones the repo and
      opens it runs this. Keep project-local configs declarative; require
      user approval for execution.
      DESC
    end

    CLAUDE_PATH_RX    = %r{(?:^|/)\.claude/(settings(?:\.local)?\.json|hooks/)}i
    CURSOR_PATH_RX    = %r{(?:^|/)(?:\.cursor/(?:rules|mcp\.json)|\.cursorrules|\.windsurfrules|\.continuerc)$}i
    VSCODE_PATH_RX    = %r{(?:^|/)\.vscode/settings\.json$}i
    ALLOW_TEMPLATE_RX = %r{/templates?/|/examples?/|/samples?/|/docs?/|/spec/|/tests?/}i

    WILDCARD_BASH_RX   = /"Bash\(\*\)"|"Bash\([^)]*\*[^)]*\)"/
    EXEC_KEY_RX        = /"(execute|command|run|script|cmd)"\s*:\s*"(bash|sh|zsh|cmd|powershell|\/bin\/|python\s|node\s|ruby\s|deno\s|curl\s|wget\s)/i
    PERMISSIONS_ALL_RX = /"permissions"\s*:\s*\{[^}]*"allow"\s*:\s*\[[^\]]*"(Bash\(\*\)|\*|WebFetch|Write\(\*\))"/i
    AUTOPROFILE_SH_RX  = /"terminal\.integrated\.automationProfile\.(?:linux|osx|windows)"[^}]*"args"\s*:\s*\[[^\]]*"-c"/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if ALLOW_TEMPLATE_RX.match(path)
      is_claude = CLAUDE_PATH_RX.match(path)
      is_cursor = CURSOR_PATH_RX.match(path)
      is_vscode = VSCODE_PATH_RX.match(path)
      return [] of Finding unless is_claude || is_cursor || is_vscode
      results = [] of Finding
      seen_line = Set(Int32).new
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        next if seen_line.includes?(idx)
        if m = line.match(WILDCARD_BASH_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Bash(*) wildcard allow — any command can run on repo open")
          seen_line << idx
          next
        end
        if m = line.match(PERMISSIONS_ALL_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "permissions.allow grants unrestricted exec (#{m[1]})")
          seen_line << idx
          next
        end
        if (is_claude || is_cursor) && (m = line.match(EXEC_KEY_RX))
          results << finding(source, path, idx, m.begin(0) || 0,
            "'#{m[1]}' launches shell ('#{m[2].strip}') — clone-triggered exec risk")
          seen_line << idx
          next
        end
        if is_vscode && (m = line.match(AUTOPROFILE_SH_RX))
          results << finding(source, path, idx, m.begin(0) || 0,
            "VSCode automationProfile runs `sh -c …` on terminal open")
          seen_line << idx
        end
      end
      results
    end
  end
end
