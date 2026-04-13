require "colorize"

module Flaw
  module Formatters
    module Pretty
      SEV_COLOR = {
        Severity::Info     => :cyan,
        Severity::Low      => :blue,
        Severity::Medium   => :yellow,
        Severity::High     => :magenta,
        Severity::Critical => :red,
      }

      def self.render(findings : Array(Finding), io : IO = STDOUT) : Nil
        if findings.empty?
          io.puts "flaw: no findings ✓".colorize(:green)
          return
        end
        by_file = findings.group_by(&.file)
        by_file.each do |file, list|
          io.puts
          io.puts file.colorize(:white).mode(:bold)
          list.sort_by!(&.line)
          list.each { |f| render_finding(f, io) }
        end
        io.puts
        summary(findings, io)
      end

      private def self.render_finding(f : Finding, io : IO) : Nil
        color = SEV_COLOR[f.severity]
        loc = "  #{f.line}:#{f.column}".colorize(:dark_gray)
        tag = "[#{f.severity.label}]".colorize(color).mode(:bold)
        id  = f.rule_id.colorize(:dark_gray)
        io.puts "#{loc} #{tag} #{id} #{f.title}"
        io.puts "    #{f.message}".colorize(:default)
        io.puts "    │ #{f.snippet}".colorize(:dark_gray) unless f.snippet.empty?
      end

      private def self.summary(findings, io) : Nil
        counts = findings.group_by(&.severity).transform_values(&.size)
        parts = [] of String
        Severity.values.reverse_each do |sev|
          if c = counts[sev]?
            parts << "#{c} #{sev.label}"
          end
        end
        io.puts "flaw: #{findings.size} findings (#{parts.join(", ")})".colorize(:yellow)
      end
    end
  end
end
