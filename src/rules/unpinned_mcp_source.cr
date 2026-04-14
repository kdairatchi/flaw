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
    GIT_UNPINNED   = %r{"(git\+https?://[^"#]+)(?:#([A-Fa-f0-9]{0,39}))?"}
    SHELL_CMD_RX   = /"command"\s*:\s*"(bash|sh|zsh|cmd|powershell)"/
    NPX_COMMAND_RX = /"command"\s*:\s*"npx"/
    # Match a package identifier — scoped (@scope/name) or plain, optionally
    # with a version tail (@1.2.3). We flag when no version tail exists.
    NPX_ARG_RX = /"(@?[A-Za-z0-9][\w\/\-\.]*?)(?:@([\w\.\-]+))?"/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless CONFIG_NAME_RX.match(path)
      results = [] of Finding
      npx_context = false
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        if m = line.match(HTTP_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Plain http:// MCP endpoint '#{m[1]}' — use https and pin")
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
        # Multi-line pattern: "command": "npx" on one line, then the "args"
        # list with the package name on the next 1–5 lines. Sticky flag
        # flips on the command key and stays until we see a plausible
        # package-name string literal (or 5 lines pass).
        if line =~ NPX_COMMAND_RX
          npx_context = true
          next
        end
        if npx_context && (m = line.match(NPX_ARG_RX))
          pkg = m[1]
          # Skip non-package string values — flag words like "args", "env".
          unless pkg =~ /\A(args|env|command|type|url|cwd)\z/
            unless m[2]?
              results << finding(source, path, idx, m.begin(0) || 0,
                "npx package '#{pkg}' without @version — pin exact version")
            end
            npx_context = false
          end
        end
      end
      results
    end
  end
end
