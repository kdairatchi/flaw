require "./rule"

module Flaw
  class SqlStringBuild < Rule
    def id : String
      "FLAW003"
    end

    def title : String
      "SQL built by string interpolation or concatenation"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      A SQL statement was assembled using interpolation (`"SELECT ... \#{var}"`)
      or string concatenation before being passed to a DB client. Use
      parameterised queries (`db.query("... WHERE id = ?", id)`) instead.
      DESC
    end

    SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|INTO)\b/i

    # interpolated SQL
    INTERP = /"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|INTO)\b[^"]*\#\{[^}]+\}[^"]*"/i

    # "... " + var  near sql keyword
    CONCAT = /"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"]*"\s*\+\s*\w+/i

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(INTERP)
          results << finding(source, path, idx, m.begin(0) || 0,
            "SQL built via interpolation — use parameterised queries")
        elsif m = line.match(CONCAT)
          results << finding(source, path, idx, m.begin(0) || 0,
            "SQL built via string concatenation — use parameterised queries")
        end
      end
      results
    end
  end
end
