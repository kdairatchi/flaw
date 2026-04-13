module Flaw
  module Entropy
    # Shannon entropy in bits/char. A uniform 64-char alphabet tops out near 6.
    # Crypto-random 32-char keys typically score ~4.5+. Words and placeholders
    # score < 3.5.
    def self.shannon(s : String) : Float64
      return 0.0 if s.empty?
      freq = {} of Char => Int32
      s.each_char { |c| freq[c] = (freq[c]? || 0) + 1 }
      len = s.size.to_f
      entropy = 0.0
      freq.each_value do |count|
        p = count / len
        entropy -= p * Math.log2(p)
      end
      entropy
    end
  end
end
