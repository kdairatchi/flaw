require "./rule"
require "./context"

module Flaw
  # FLAW145 — GitHub Actions script injection: an unsanitized
  # `${{ github.event.X.Y }}` expression interpolated into a `run:` shell,
  # letting PR authors execute arbitrary commands on the runner.
  class WorkflowScriptInjection < Rule
    def id : String
      "FLAW145"
    end

    def title : String
      "Unsafe github.event expression in workflow"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      GitHub Actions evaluates `${{ ... }}` expressions by splicing their
      string value directly into the shell command. If the value comes from
      attacker-controlled fields (issue title, PR body, comment, review,
      branch name), shell metacharacters inside it execute on the runner.
      Pass the expression through an `env:` block and reference it as an
      environment variable instead.
      DESC
    end

    WORKFLOW_PATH = %r{\.github/workflows/.*\.ya?ml$}
    DANGEROUS_RX  = /\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion|release)\.(title|body|label|head\.(ref|sha))\s*\}\}/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless path =~ WORKFLOW_PATH
      return [] of Finding if RuleContext.test_path?(path)

      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(DANGEROUS_RX)
          field = m[2]
          results << finding(source, path, idx, m.begin(0) || 0,
            "Unsanitized github.event.*.#{field} in workflow — shell injection risk, wrap in env var")
        end
      end
      results
    end
  end
end
