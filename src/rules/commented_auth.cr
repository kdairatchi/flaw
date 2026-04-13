require "./rule"

module Flaw
  # FLAW105 — AI-slop. Commented-out authorization/authentication check.
  # Very common Claude/Copilot pattern: "make the test pass" → comment out
  # the guard → ship.
  class CommentedAuth < Rule
    def id : String
      "FLAW105"
    end

    def title : String
      "Commented-out authorization or authentication check"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      A line that looks like an auth/permission guard was commented out
      rather than replaced. Classic "make it green" anti-pattern —
      particularly dangerous from AI assistants that treat the guard as an
      obstacle. Delete the comment and restore the check, or delete it
      and document why authorization isn't needed here.
      DESC
    end

    def tag : String
      "ai-slop"
    end

    # commented lines that mention known auth guards
    PATTERN = /^\s*#\s*(?:before_action\s+:?authenticate|authenticate!|require_admin|require_login|authorize!|check_permission|current_user\s*\|\|\s*return|halt\s*401|halt\s*403|raise\s+Unauthorized)/

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(PATTERN)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Commented-out auth guard — restore the check or document why it was removed")
        end
      end
      results
    end
  end
end
