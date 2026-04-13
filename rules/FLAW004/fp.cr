# FLAW004 — FP corpus: rand() in non-security contexts
# Random choice for UI jitter, shuffling game dice, retry backoff — not tokens.
sleep(rand(50..200).milliseconds)
dice = rand(1..6)
shuffled = [1, 2, 3].shuffle
