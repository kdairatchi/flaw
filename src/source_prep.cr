module Flaw
  # Pre-scan source normalisation. Currently masks heredoc bodies so string
  # content doesn't trigger comment/regex rules. Line count is preserved —
  # masked lines become empty strings.
  module SourcePrep
    # Matches `<<-IDENT` / `<<IDENT` / `<<-"IDENT"` heredoc starts.
    # Not exhaustive (ignores multiple heredocs on one line, heredoc-in-interp),
    # but covers the dominant Crystal idiom.
    HEREDOC_START = /<<-?"?([A-Z_][A-Z0-9_]*)"?/

    def self.mask_heredocs(source : String) : String
      lines = source.split('\n')
      out = lines.dup
      i = 0
      while i < lines.size
        line = lines[i]
        # skip past line comments entirely
        unless line.lstrip.starts_with?('#')
          if m = line.match(HEREDOC_START)
            ident = m[1]
            terminator = /\A\s*#{Regex.escape(ident)}\s*\z/
            j = i + 1
            while j < lines.size
              if lines[j].match(terminator)
                break
              end
              out[j] = ""
              j += 1
            end
            i = j
          end
        end
        i += 1
      end
      out.join('\n')
    end
  end
end
