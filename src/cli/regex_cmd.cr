require "colorize"
require "uri"

module Flaw
  module CLI
    # `flaw regex` — helpers for writing and debugging rule patterns.
    module RegexCmd
      CHEATSHEET = <<-SHEET
      Character classes
        .             any character except newline
        \\w \\d \\s     word, digit, whitespace
        \\W \\D \\S     not word, digit, whitespace
        [abc]         any of a, b, or c
        [^abc]        not a, b, or c
        [a-g]         character between a & g

      Anchors
        ^abc$         start / end of the string
        \\b \\B        word, not-word boundary

      Escaped characters
        \\. \\* \\\\     escaped special characters
        \\t \\n \\r     tab, linefeed, carriage return

      Groups & Lookaround
        (abc)         capture group
        \\1            backreference to group #1
        (?:abc)       non-capturing group
        (?=abc)       positive lookahead
        (?!abc)       negative lookahead

      Quantifiers & Alternation
        a* a+ a?      0 or more, 1 or more, 0 or 1
        a{5} a{2,}    exactly five, two or more
        a{1,3}        between one & three
        a+? a{2,}?    match as few as possible
        ab|cd         match ab or cd

      Try online:
        https://regex101.com/       (flavor=pcre for Crystal-ish behavior)
        https://regexr.com/
        https://regex101.com/library  (recipes)
      SHEET

      def self.run(argv : Array(String)) : Nil
        sub = argv.shift? || "help"
        case sub
        when "test"     then test_cmd(argv)
        when "help", "--help", "-h" then puts_help
        else
          STDERR.puts "flaw regex: unknown subcommand '#{sub}' — try `flaw regex help`"
          exit 2
        end
      end

      private def self.test_cmd(argv : Array(String)) : Nil
        if argv.size < 2
          STDERR.puts "usage: flaw regex test <pattern> <input>"
          STDERR.puts "       pattern does not include delimiters; use (?i) for case-insensitive"
          exit 2
        end
        pattern = argv[0]
        input = argv[1]
        re = begin
          Regex.new(pattern)
        rescue ex : ArgumentError
          STDERR.puts "flaw: invalid regex — #{ex.message}".colorize(:red)
          exit 2
        end

        if m = input.match(re)
          puts "match".colorize(:green).mode(:bold)
          puts "  [0] #{m[0].inspect}"
          (1...m.size).each { |i| puts "  [#{i}] #{m[i]?.inspect}" }
        else
          puts "no match".colorize(:yellow)
        end
        puts
        puts "regex101: #{regex101_url(pattern, input)}"
      end

      private def self.regex101_url(pattern : String, input : String) : String
        enc = ->(s : String) { URI.encode_www_form(s) }
        "https://regex101.com/?regex=#{enc.call(pattern)}&testString=#{enc.call(input)}&flavor=pcre"
      end

      private def self.puts_help : Nil
        puts "flaw regex — regex helpers for rule authors and users".colorize(:white).mode(:bold)
        puts
        puts "usage:"
        puts "  flaw regex test <pattern> <input>   # compile + match, print capture groups"
        puts "  flaw regex help                     # this cheatsheet"
        puts
        puts CHEATSHEET
      end
    end
  end
end
