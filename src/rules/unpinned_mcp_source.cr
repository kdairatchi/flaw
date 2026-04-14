require "./rule"
require "./context"

module Flaw
  # FLAW149 — MCP / agent config references unpinned or plaintext sources.
  # Unpinned npx/git/http MCP servers let a supply-chain update swap the
  # binary under the user's agent with no review.
  class UnpinnedMcpSource < Rule
    def id : String
      "FLAW149"
    end

    def title : String
      "Unpinned MCP/agent source"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      An MCP/agent config file references a server without a pinned
      version: plain `http://`, `npx` without `@<version>`, or
      `git+https://...` without a 40-char commit SHA. Any of these means
      the upstream can rotate the code your agent runs. Pin exact
      versions or SHAs; require HTTPS.
      DESC
    end

    CONFIG_NAME_RX = %r{(?:^|/)(?:\.mcp\.json|mcp\.json|claude_desktop_config\.json|mcp\.ya?ml|\.cursor/mcp\.json)$}i
    HTTP_RX        = %r{"(http://[^"]+)"}
    NPX_UNPINNED   = /"npx"[^\]]*?"([A-Za-z0-9@._\/\-]+)"/
    GIT_UNPINNED   = %r{"(git\+https?://[^"#]+)(?:#([A-Fa-f0-9]{0,39}))?"}
    SHELL_CMD_RX   = /"command"\s*:\s*"(bash|sh|zsh|cmd|powershell)"/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless CONFIG_NAME_RX.match(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        if m = line.match(HTTP_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Plain http:// MCP endpoint '#{m[1]}' — use https and pin")
        end
        if m = line.match(NPX_UNPINNED)
          pkg = m[1]
          unless pkg.includes?("@") && pkg.rindex('@').not_nil! > 0
            results << finding(source, path, idx, m.begin(0) || 0,
              "npx package '#{pkg}' without @version — pin exact version")
          end
        end
        if m = line.match(GIT_UNPINNED)
          sha = m[2]?
          if sha.nil? || sha.size < 40
            results << finding(source, path, idx, m.begin(0) || 0,
              "git MCP source without 40-char commit SHA — supply-chain risk")
          end
        end
        if m = line.match(SHELL_CMD_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Raw shell ('#{m[1]}') as MCP command — wrap in a signed binary")
        end
      end
      results
    end
  end
end
