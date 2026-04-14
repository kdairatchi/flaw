require "./rule"
require "./context"

module Flaw
  # FLAW126 — Crystal/Ruby shell execution with interpolation.
  class ShellExec < Rule
    def id : String
      "FLAW126"
    end

    def title : String
      "Shell execution with interpolation"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Passing an interpolated string to system/exec/backticks/Process.run
      with shell:true hands the shell the entire command, letting any
      metacharacter in the interpolated value inject arbitrary commands.
      Use the array form and keep shell:false.
      DESC
    end

    EXT = %w(.cr .rb)

    CR_RUN_SHELL = /Process\.run\s*\([^)]*shell:\s*true/
    CR_RUN_INT   = /Process\.run\s*\([^)]*#\{/
    RB_SYSTEM    = /\b(?:system|exec)\s*\(?\s*["'][^"']*#\{/
    RB_BACKTICK  = /`[^`]*#\{[^`]*`/
    RB_POPEN     = /(?:IO\.popen|Open3\.(?:capture|popen)\d*)\s*\([^)]*#\{/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      is_cr = path.ends_with?(".cr")
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        patterns = is_cr ? [CR_RUN_SHELL, CR_RUN_INT] : [CR_RUN_SHELL, CR_RUN_INT, RB_SYSTEM, RB_BACKTICK, RB_POPEN]
        patterns.each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Shell execution with interpolated string — command injection risk, use array form without shell:true")
            break
          end
        end
      end
      results
    end
  end
end
