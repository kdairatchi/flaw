require "./rule"
require "./context"

module Flaw
  # FLAW101 — AI refusal/assistant phrases leaked into source.
  # Pattern: Claude or ChatGPT output pasted verbatim, including meta-speak
  # that has no business running in production ("As an AI...", "I apologize...").
  class AiAssistantLeak < Rule
    def id : String
      "FLAW101"
    end

    def title : String
      "AI assistant boilerplate leaked into source"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "ai-slop"
    end

    def description : String
      <<-DESC
      A string literal or comment contains text typical of an LLM refusal
      or meta-response ("As an AI language model", "I cannot", "I apologize
      for the confusion", "As of my last knowledge update", "Certainly!").
      This is code that was copy-pasted from a chat session without review.
      DESC
    end

    PATTERNS = [
      /\bAs an AI (language model|assistant)\b/i,
      /\bI (cannot|can't|am unable to) (provide|generate|produce|assist with|help with)\b/i,
      /\bI apologize for (the|any) (confusion|inconvenience)\b/i,
      /\bAs of my (last )?(knowledge|training)(\s+(update|cutoff))?\b/i,
      /\b(Certainly!|Absolutely!|Of course!|Sure thing!)\s*[A-Z]/,
      /\b(Let me|I'll|I will) (assist|help) you (with)?\b/i,
      /\bI don't have (access to|the ability to|real[- ]time)\b/i,
      /\bI'm (just|only) an? (AI|language model)\b/i,
    ]

    # Paths that are allowed to contain these phrases as test fixtures or
    # prompt material.
    ALLOW_PATH = %r{/(prompts?|fixtures?|spec|tests?|examples?|corpus|eval)s?/}i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if ALLOW_PATH.match(path)
      return [] of Finding if path.ends_with?(".jsonl") || path.ends_with?(".txt")
      lenient = RuleContext.doc_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        # Only fire when the phrase is inside a string literal or a comment —
        # never on plain prose in Markdown headers/body (which legitimately
        # contains "I cannot" etc.).
        next if lenient && !(line =~ /[#"']|\/\//)
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "AI assistant phrase in source — strip it before shipping")
            break
          end
        end
      end
      results
    end
  end
end
