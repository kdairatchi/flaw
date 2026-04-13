module Flaw
  class Scanner
    getter rules : Array(Rule)
    getter config : Config

    def initialize(@rules = Rule.all, @config = Config.new)
    end

    def scan(root : String) : Array(Finding)
      results = [] of Finding
      files(root).each do |path|
        source = File.read(path)
        rules.each do |rule|
          override = config.rule_overrides[rule.id]?
          next if override && override.disabled
          next if override && override.ignore.any? { |pat| path.includes?(pat) }
          rule.check(source, path).each do |f|
            f = apply_override(f, override)
            results << f
          end
        end
      rescue ex : IO::Error | File::Error
        STDERR.puts "flaw: skipped #{path} (#{ex.message})"
      end
      results
    end

    private def apply_override(f : Finding, override : Config::RuleOverride?) : Finding
      return f unless override && (sev = override.severity)
      Finding.new(f.rule_id, sev, f.title, f.message, f.file, f.line, f.column, f.snippet)
    end

    private def files(root : String) : Array(String)
      return [root] if File.file?(root)
      out = [] of String
      Dir.glob(File.join(root, "**", "*.cr")).each do |p|
        next if config.excluded?(p)
        out << p
      end
      out
    end
  end
end
