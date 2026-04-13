require "./rule"

module Flaw
  class CommandInjection < Rule
    def id : String
      "FLAW001"
    end

    def title : String
      "OS command built from interpolated input"
    end

    def default_severity : Severity
      Severity::Critical
    end

    def description : String
      <<-DESC
      A call to `system`, `` ` `` (backticks), or `Process.run` was built using
      string interpolation. If any interpolated value originates from user input,
      this is a command injection sink.
      DESC
    end

    # matches: system("foo #{bar}"), `foo #{bar}`, Process.run("foo #{bar}")
    PATTERNS = [
      /\bsystem\s*\(\s*"[^"]*\#\{[^}]+\}[^"]*"/,
      /\bProcess\.run\s*\(\s*"[^"]*\#\{[^}]+\}[^"]*"/,
      /`[^`]*\#\{[^}]+\}[^`]*`/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Command built via string interpolation — taint-check the interpolated values or use Process.run with an argv array")
            break
          end
        end
      end
      results
    end
  end
end
