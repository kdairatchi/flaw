module Flaw
  # Parses inline suppression directives in a Crystal source file.
  #
  #   foo(user_input)                    # flaw:ignore FLAW001
  #                                      # flaw:ignore-next FLAW001,FLAW006
  #   bar(x)
  #
  # File-level directive on any line (canonically the first):
  #                                      # flaw:ignore-file FLAW002
  #
  # Special ID `ALL` suppresses every rule.
  class Suppression
    getter line_suppressed : Hash(Int32, Set(String))
    getter file_suppressed : Set(String)

    def initialize(@line_suppressed = {} of Int32 => Set(String), @file_suppressed = Set(String).new)
    end

    SAME_LINE = /#\s*flaw:ignore\s+([A-Z0-9_,\s]+)/
    NEXT_LINE = /#\s*flaw:ignore-next(?:-line)?\s+([A-Z0-9_,\s]+)/
    FILE_WIDE = /#\s*flaw:ignore-file\s+([A-Z0-9_,\s]+)/

    def self.parse(source : String) : Suppression
      s = Suppression.new
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(FILE_WIDE)
          ids(m[1]).each { |id| s.file_suppressed << id }
          next
        end
        if m = line.match(NEXT_LINE)
          # find next non-blank line
          following = idx + 1
          rest = source.split('\n')[idx..]? || [] of String
          rest.each_with_index do |l, off|
            unless l.strip.empty?
              following = idx + off + 1
              break
            end
          end
          s.line_suppressed[following] ||= Set(String).new
          ids(m[1]).each { |id| s.line_suppressed[following] << id }
          next
        end
        if m = line.match(SAME_LINE)
          s.line_suppressed[idx] ||= Set(String).new
          ids(m[1]).each { |id| s.line_suppressed[idx] << id }
        end
      end
      s
    end

    def suppressed?(rule_id : String, line : Int32) : Bool
      return true if file_suppressed.includes?("ALL") || file_suppressed.includes?(rule_id)
      if set = line_suppressed[line]?
        return true if set.includes?("ALL") || set.includes?(rule_id)
      end
      false
    end

    private def self.ids(raw : String) : Array(String)
      raw.split(',').map(&.strip.upcase).reject(&.empty?)
    end
  end
end
