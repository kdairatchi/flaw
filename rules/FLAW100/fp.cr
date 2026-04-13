# FLAW100 — FP corpus: legitimate "why" comments explaining non-obvious logic
module Foo
  # Off-by-one here is intentional: the upstream API indexes from 1.
  def get(i)
    fetch(i - 1)
  end

  # Workaround for https://github.com/crystal-lang/crystal/issues/12345
  def parse(s : String)
    s.to_i64? || 0_i64
  end
end
