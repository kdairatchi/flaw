require "./rule"
require "./context"

module Flaw
  # FLAW157 — committed AI-tool project config. `.claude/`, `.cursor/`,
  # `.mcp.json` etc. shipped in a public repo means anyone who clones
  # and opens the project with the matching tool can get instructions /
  # exec surface pushed into their session.
  class DotclaudeInRepo < Rule
    def id : String
      "FLAW157"
    end

    def title : String
      "AI-tool project config committed to repo"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A project-local AI/tool config file is part of the repo tree
      (`.claude/`, `.cursor/`, `.mcp.json`, `.windsurfrules`,
      `.continuerc`). On `git clone`, anyone opening the repo in the
      corresponding tool inherits the hooks, prompts, and permissions.
      Keep these local and gitignored unless the repo is explicitly a
      template (baseline this rule in that case).
      DESC
    end

    FLAGGED_PATH_RX  = %r{(?:^|/)(\.claude/|\.cursor/|\.mcp\.json$|\.windsurfrules$|\.continuerc$|\.cursorrules$)}i
    TEMPLATE_PATH_RX = %r{/templates?/|/examples?/|/samples?/|/fixtures?/}i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if TEMPLATE_PATH_RX.match(path)
      return [] of Finding unless m = path.match(FLAGGED_PATH_RX)
      [finding(source, path, 1, 0,
        "'#{m[1].sub(/\/$/, "")}' committed to repo — clones inherit hooks/perms")]
    end
  end
end
