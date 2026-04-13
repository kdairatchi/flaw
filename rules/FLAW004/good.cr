# FLAW004 — fixed: use Random::Secure
def new_session_token
  Random::Secure.hex(16)
end

def reset_password_otp
  Random::Secure.rand(100_000..999_999)
end

nonce = Random::Secure.random_bytes(16)
puts nonce
