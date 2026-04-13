# FLAW004 — vulnerable: predictable RNG for security values
def new_session_token
  Random.new.hex(16)
end

def reset_password_otp
  rand(100_000..999_999)
end

nonce = Random::DEFAULT.random_bytes(16)
puts nonce
