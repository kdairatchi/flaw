module Flaw
  class Scanner
    getter rules : Array(Rule)
    getter config : Config

    def initialize(@rules = Rule.all, @config = Config.new)
    end

    def scan(root : String) : Array(Finding)
      results = [] of Finding
      files(root).each do |path|
        source = File.read(path, encoding: "UTF-8", invalid: :skip)
        masked = SourcePrep.mask_heredocs(source)
        suppression = Suppression.parse(source)
        ast_rules = [] of AstRule

        rules.each do |rule|
          override = config.rule_overrides[rule.id]?
          next if override && override.disabled
          next if override && override.ignore.any? { |pat| path.includes?(pat) }
          if rule.is_a?(AstRule)
            ast_rules << rule
            next
          end
          rule.check(masked, path).each do |f|
            next if suppression.suppressed?(f.rule_id, f.line)
            f = apply_override(f, override)
            results << f
          end
        end

        unless ast_rules.empty?
          AstBackend.run(ast_rules, source, path).each do |f|
            next if suppression.suppressed?(f.rule_id, f.line)
            override = config.rule_overrides[f.rule_id]?
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
