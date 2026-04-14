module Flaw
  # Shared helpers for rule false-positive reduction. Centralising these here
  # means every rule gets the same answer to "is this a test file?", "should
  # I skip docs?", and "is this line just a comment?".
  module RuleContext
    extend self

    TEST_PATH_RX    = %r{(?:^|/)(?:spec|tests?|__tests__|fixtures?|testdata|vendor|third_party|node_modules)(?:/|$)}
    DOC_EXTENSIONS  = %w(.md .mdx .rst .txt .adoc)
    LOCK_FILES      = %w(Gemfile.lock shard.lock Cargo.lock package-lock.json yarn.lock poetry.lock pnpm-lock.yaml go.sum)
    WEB_EXTENSIONS  = %w(.css .scss .sass .less .vue .svelte .astro)
    CODE_EXTENSIONS = %w(.cr .rb .py .js .jsx .ts .tsx .go .rs .java .kt .swift .php .ex .exs .c .cpp .cc .h .hpp)

    def test_path?(path : String) : Bool
      !!(path =~ TEST_PATH_RX)
    end

    def doc_path?(path : String) : Bool
      DOC_EXTENSIONS.any? { |ext| path.ends_with?(ext) }
    end

    def lock_path?(path : String) : Bool
      base = path.split('/').last
      LOCK_FILES.includes?(base)
    end

    def code_path?(path : String) : Bool
      CODE_EXTENSIONS.any? { |ext| path.ends_with?(ext) }
    end

    def web_path?(path : String) : Bool
      WEB_EXTENSIONS.any? { |ext| path.ends_with?(ext) }
    end

    # True when a rule that targets production code should skip this path.
    def skip_nonprod?(path : String) : Bool
      test_path?(path) || doc_path?(path) || lock_path?(path)
    end

    # Strips // and # line comments plus "..." and '...' string contents so a
    # pattern that should only fire on bare code isn't fooled by test data.
    # Intentionally conservative — doesn't parse, just zeroes the obvious
    # cases.
    def strip_strings_and_comments(line : String) : String
      buf = String.build do |io|
        i = 0
        chars = line.chars
        in_str = nil.as(Char?)
        while i < chars.size
          c = chars[i]
          if in_str
            if c == '\\' && i + 1 < chars.size
              io << "  "
              i += 2
              next
            end
            if c == in_str
              in_str = nil
              io << ' '
            else
              io << ' '
            end
            i += 1
            next
          end
          # line-comment starters
          if c == '#'
            break
          end
          if c == '/' && chars[i + 1]? == '/'
            break
          end
          if c == '"' || c == '\''
            in_str = c
            io << ' '
            i += 1
            next
          end
          io << c
          i += 1
        end
      end
      buf
    end

    # True if the line is entirely whitespace or a comment (Crystal/Ruby/Py
    # `#`, C/JS `//`, Crystal doc `##`).
    def comment_only?(line : String) : Bool
      s = line.strip
      return true if s.empty?
      return true if s.starts_with?('#')
      return true if s.starts_with?("//")
      return true if s.starts_with?("/*") || s.starts_with?('*')
      false
    end
  end
end
